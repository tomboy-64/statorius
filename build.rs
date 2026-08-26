use image::{Rgba, RgbaImage};

/// Single source of truth for every generated icon asset: a 750x750
/// transparent PNG. Everything below is derived from this at build time -
/// only `ico/statorius.ico` (referenced directly by `wix/main.wxs`, which
/// needs a stable path rather than something under `OUT_DIR`) and the
/// Linux `ico/hicolor/*` set (installed by `arch/PKGBUILD`, outside of
/// Cargo entirely) are still checked into the repo as separate files.
const MASTER_ICON_PATH: &str = "ico/statorius-master.png";

/// Resizes `src` to `size`x`size`, premultiplying alpha before the Lanczos3
/// resize and undoing it after. `src`'s corners are fully transparent
/// (0,0,0,0) - resizing RGBA directly (i.e. without this) blends that
/// literal black into semi-transparent edge pixels, giving them a faint
/// dark fringe. Premultiplying first means edge pixels are interpolated as
/// "color scaled by how opaque it is" instead, which is what compositing
/// actually wants; unpremultiplying afterward restores plain RGBA.
fn resize_premultiplied(src: &RgbaImage, size: u32) -> RgbaImage {
    let (w, h) = src.dimensions();
    let mut premultiplied = RgbaImage::new(w, h);
    for (x, y, px) in src.enumerate_pixels() {
        let [r, g, b, a] = px.0;
        let af = f32::from(a) / 255.0;
        premultiplied.put_pixel(
            x,
            y,
            Rgba([
                (f32::from(r) * af).round() as u8,
                (f32::from(g) * af).round() as u8,
                (f32::from(b) * af).round() as u8,
                a,
            ]),
        );
    }

    let resized = image::imageops::resize(
        &premultiplied,
        size,
        size,
        image::imageops::FilterType::Lanczos3,
    );

    let mut out = RgbaImage::new(size, size);
    for (x, y, px) in resized.enumerate_pixels() {
        let [r, g, b, a] = px.0;
        let unpremultiplied = if a == 0 {
            [0, 0, 0, 0]
        } else {
            let af = f32::from(a) / 255.0;
            [
                (f32::from(r) / af).round().clamp(0.0, 255.0) as u8,
                (f32::from(g) / af).round().clamp(0.0, 255.0) as u8,
                (f32::from(b) / af).round().clamp(0.0, 255.0) as u8,
                a,
            ]
        };
        out.put_pixel(x, y, Rgba(unpremultiplied));
    }
    out
}

/// Generates `ico/statorius.ico`'s Windows equivalent, but into `OUT_DIR`
/// for embedding via `winresource` - one frame per size, each individually
/// resized (rather than letting an ICO encoder auto-resize a single base
/// image, which would skip the premultiplied-alpha handling above for
/// every size but the largest).
fn write_windows_ico(master: &RgbaImage, out_path: &std::path::Path) {
    use image::codecs::ico::{IcoEncoder, IcoFrame};
    use image::ExtendedColorType;

    let sizes = [16u32, 24, 32, 48, 64, 128, 256];
    let mut frames = Vec::with_capacity(sizes.len());
    for size in sizes {
        let resized = resize_premultiplied(master, size);
        let frame = IcoFrame::as_png(resized.as_raw(), size, size, ExtendedColorType::Rgba8)
            .expect("failed to PNG-encode an .ico frame");
        frames.push(frame);
    }

    let file = std::fs::File::create(out_path)
        .unwrap_or_else(|e| panic!("failed to create {}: {e}", out_path.display()));
    IcoEncoder::new(file)
        .encode_images(&frames)
        .expect("failed to write statorius.ico");
}

fn main() {
    println!("cargo:rerun-if-changed={MASTER_ICON_PATH}");

    let master = image::open(MASTER_ICON_PATH)
        .unwrap_or_else(|e| panic!("failed to decode {MASTER_ICON_PATH}: {e}"))
        .into_rgba8();

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_dir = std::path::Path::new(&out_dir);

    // Runtime app icon (window/taskbar icon + About tab texture - see
    // src/main.rs) - same 256px size on every platform, embedded via
    // `include_bytes!(concat!(env!("OUT_DIR"), "/statorius-icon.png"))`.
    let runtime_icon = resize_premultiplied(&master, 256);
    runtime_icon
        .save(out_dir.join("statorius-icon.png"))
        .expect("failed to write generated statorius-icon.png");

    // Windows-only: embed a freshly-generated multi-resolution .ico into
    // the .exe as a PE resource. This is intentionally a *separate*
    // generation from the checked-in ico/statorius.ico that
    // wix/main.wxs uses for the installer's Add/Remove Programs icon and
    // shortcut - both derive from the same master via the same resize
    // logic, so they should look identical, but if this function's resize
    // approach ever changes, ico/statorius.ico needs regenerating by hand
    // to match it.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let ico_path = out_dir.join("statorius.ico");
        write_windows_ico(&master, &ico_path);

        let mut res = winresource::WindowsResource::new();
        res.set_icon(ico_path.to_str().expect("OUT_DIR path is not valid UTF-8"));
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=failed to embed Windows icon resource: {e}");
        }
    }
}