//! `imageutil.Thumbhash` after the decode, and `go.n16f.net/thumbhash`'s encoder.
//!
//! The stored value is a placeholder, but ebook cover change detection compares it for equality, so the
//! bytes are worth matching. `f64::cos` comes from the platform's libm, whose last bit differs from
//! Go's Cephes port, so this carries a port of Go's `math.Cos`.

use silo_jwt::base64go::std_encode;

// Go's constants, spelled as Go spells them.
#[allow(clippy::excessive_precision)]
const SIN: [f64; 6] = [
    1.58962301576546568060e-10,
    -2.50507477628578072866e-8,
    2.75573136213857245213e-6,
    -1.98412698295895385996e-4,
    8.33333333332211858878e-3,
    -1.66666666666666307295e-1,
];
#[allow(clippy::excessive_precision)]
const COS: [f64; 6] = [
    -1.13585365213876817300e-11,
    2.08757008419747316778e-9,
    -2.75573141792967388112e-7,
    2.48015872888517045348e-5,
    -1.38888888888730564116e-3,
    4.16666666666665929218e-2,
];

/// Go's `math.Cos` for the arguments this file passes, all below `reduceThreshold`.
#[allow(clippy::excessive_precision)]
fn go_cos(x: f64) -> f64 {
    const PI4A: f64 = 7.85398125648498535156e-1;
    const PI4B: f64 = 3.77489470793079817668e-8;
    const PI4C: f64 = 2.69515142907905952645e-15;
    let mut sign = false;
    let x = x.abs();
    let mut j = (x * (4.0 / std::f64::consts::PI)) as u64;
    let mut y = j as f64;
    if j & 1 == 1 {
        j += 1;
        y += 1.0;
    }
    j &= 7;
    let z = ((x - y * PI4A) - y * PI4B) - y * PI4C;
    if j > 3 {
        j -= 4;
        sign = !sign;
    }
    if j > 1 {
        sign = !sign;
    }
    let zz = z * z;
    let result = if j == 1 || j == 2 {
        z + z
            * zz
            * ((((((SIN[0] * zz) + SIN[1]) * zz + SIN[2]) * zz + SIN[3]) * zz + SIN[4]) * zz
                + SIN[5])
    } else {
        1.0 - 0.5 * zz
            + zz * zz
                * ((((((COS[0] * zz) + COS[1]) * zz + COS[2]) * zz + COS[3]) * zz + COS[4]) * zz
                    + COS[5])
    };
    if sign { -result } else { result }
}

fn iround(x: f64) -> i64 {
    x.round() as i64
}

/// `color.NRGBA.RGBA`.
fn nrgba_to_rgba16(p: &[u8]) -> (u32, u32, u32, u32) {
    let a = u32::from(p[3]);
    let channel = |c: u8| {
        let c = u32::from(c);
        ((c | c << 8) * a) / 0xff
    };
    (channel(p[0]), channel(p[1]), channel(p[2]), a | a << 8)
}

/// `imageutil.scaleImage` of an NRGBA source: nearest neighbour within `max_dim`, returning
/// `(width, height, NRGBA pixels)`. Like Go, it stores premultiplied channel values as if they were not.
pub fn scale_image(w: usize, h: usize, pix: &[u8], max_dim: usize) -> (usize, usize, Vec<u8>) {
    let mut scale = 1.0f64;
    if w > max_dim || h > max_dim {
        let scale_w = max_dim as f64 / w as f64;
        let scale_h = max_dim as f64 / h as f64;
        scale = if scale_w < scale_h { scale_w } else { scale_h };
    }
    let dst_w = ((w as f64 * scale) as usize).max(1);
    let dst_h = ((h as f64 * scale) as usize).max(1);
    let mut out = Vec::with_capacity(dst_w * dst_h * 4);
    for y in 0..dst_h {
        let src_y = ((y as f64 / scale) as usize).min(h - 1);
        for x in 0..dst_w {
            let src_x = ((x as f64 / scale) as usize).min(w - 1);
            let i = (src_y * w + src_x) * 4;
            let (r, g, b, a) = nrgba_to_rgba16(&pix[i..i + 4]);
            out.extend_from_slice(&[
                (r >> 8) as u8,
                (g >> 8) as u8,
                (b >> 8) as u8,
                (a >> 8) as u8,
            ]);
        }
    }
    (dst_w, dst_h, out)
}

/// `draw.Draw` of an NRGBA source onto RGBA with `draw.Src`.
fn to_premultiplied(pix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pix.len());
    for p in pix.as_chunks::<4>().0 {
        let sa = u32::from(p[3]) * 0x101;
        let channel = |c: u8| ((u32::from(c) * sa / 0xff) >> 8) as u8;
        out.extend_from_slice(&[channel(p[0]), channel(p[1]), channel(p[2]), (sa >> 8) as u8]);
    }
    out
}

struct Channel {
    dc: f64,
    ac: Vec<f64>,
    scale: f64,
}

fn encode_channel(channel: &[f64], w: usize, h: usize, nx: usize, ny: usize) -> Channel {
    let wf = w as f64;
    let hf = h as f64;
    let pi = std::f64::consts::PI;
    let mut fx = vec![0.0f64; w];
    let (mut dc, mut ac, mut scale) = (0.0f64, Vec::new(), 0.0f64);
    for cy in 0..ny {
        let cyf = cy as f64;
        let mut cx = 0usize;
        while cx * ny < nx * (ny - cy) {
            let cxf = cx as f64;
            let mut f = 0.0f64;
            for (x, slot) in fx.iter_mut().enumerate() {
                *slot = go_cos(pi / wf * cxf * (x as f64 + 0.5));
            }
            for y in 0..h {
                let fy = go_cos(pi / hf * cyf * (y as f64 + 0.5));
                for x in 0..w {
                    f += channel[x + y * w] * fx[x] * fy;
                }
            }
            f /= (w * h) as f64;
            if cx > 0 || cy > 0 {
                ac.push(f);
                scale = scale.max(f.abs());
            } else {
                dc = f;
            }
            cx += 1;
        }
    }
    if scale > 0.0 {
        for value in &mut ac {
            *value = 0.5 + 0.5 / scale * *value;
        }
    }
    Channel { dc, ac, scale }
}

/// `thumbhash.EncodeImage` of an NRGBA image up to 128 pixels on its longest side, which is all
/// `imageutil` passes it.
pub fn encode_nrgba(w: usize, h: usize, pix: &[u8]) -> Vec<u8> {
    let rgba = to_premultiplied(pix);
    let (mut avg_r, mut avg_g, mut avg_b, mut avg_a) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    for p in rgba.as_chunks::<4>().0 {
        let a = f64::from(p[3]) / 255.0;
        avg_r += a / 255.0 * f64::from(p[0]);
        avg_g += a / 255.0 * f64::from(p[1]);
        avg_b += a / 255.0 * f64::from(p[2]);
        avg_a += a;
    }
    if avg_a > 0.0 {
        avg_r /= avg_a;
        avg_g /= avg_a;
        avg_b /= avg_a;
    }
    let pixels = w * h;
    let has_alpha = avg_a < pixels as f64;
    let l_limit = if has_alpha { 5.0 } else { 7.0 };
    let wf = w as f64;
    let hf = h as f64;
    let max_wh = wf.max(hf);
    let lx = iround((l_limit * wf) / max_wh).max(1);
    let ly = iround((l_limit * hf) / max_wh).max(1);

    let mut l = Vec::with_capacity(pixels);
    let mut pc = Vec::with_capacity(pixels);
    let mut q = Vec::with_capacity(pixels);
    let mut alpha = Vec::with_capacity(pixels);
    for p in rgba.as_chunks::<4>().0 {
        let a = f64::from(p[3]) / 255.0;
        let r = avg_r * (1.0 - a) + a / 255.0 * f64::from(p[0]);
        let g = avg_g * (1.0 - a) + a / 255.0 * f64::from(p[1]);
        let b = avg_b * (1.0 - a) + a / 255.0 * f64::from(p[2]);
        l.push((r + g + b) / 3.0);
        pc.push((r + g) / 2.0 - b);
        q.push(r - g);
        alpha.push(a);
    }

    let l_channel = encode_channel(&l, w, h, lx.max(3) as usize, ly.max(3) as usize);
    let p_channel = encode_channel(&pc, w, h, 3, 3);
    let q_channel = encode_channel(&q, w, h, 3, 3);
    let a_channel = has_alpha.then(|| encode_channel(&alpha, w, h, 5, 5));

    let is_landscape = w > h;
    let mut nb_ac = l_channel.ac.len() + p_channel.ac.len() + q_channel.ac.len();
    if let Some(a) = &a_channel {
        nb_ac += a.ac.len();
    }
    let mut size = 3 + 2 + nb_ac.div_ceil(2);
    if has_alpha {
        size += 1;
    }
    let mut hash = vec![0u8; size];
    let mut header24 = iround(63.0 * l_channel.dc);
    header24 |= iround(31.5 + 31.5 * p_channel.dc) << 6;
    header24 |= iround(31.5 + 31.5 * q_channel.dc) << 12;
    header24 |= iround(31.0 * l_channel.scale) << 18;
    if has_alpha {
        header24 |= 1 << 23;
    }
    hash[0] = header24 as u8;
    hash[1] = (header24 >> 8) as u8;
    hash[2] = (header24 >> 16) as u8;
    let l_count = if is_landscape { ly } else { lx };
    let mut header16 = l_count;
    header16 |= iround(63.0 * p_channel.scale) << 3;
    header16 |= iround(63.0 * q_channel.scale) << 9;
    if is_landscape {
        header16 |= 1 << 15;
    }
    hash[3] = header16 as u8;
    hash[4] = (header16 >> 8) as u8;
    let mut start = 5;
    if let Some(a) = &a_channel {
        hash[5] = (iround(15.0 * a.dc) | iround(15.0 * a.scale) << 4) as u8;
        start = 6;
    }
    let mut idx = 0usize;
    let mut lists = vec![&l_channel.ac, &p_channel.ac, &q_channel.ac];
    if let Some(a) = &a_channel {
        lists.push(&a.ac);
    }
    for list in lists {
        for f in list {
            hash[start + idx / 2] |= (iround(15.0 * f) << ((idx & 1) * 4)) as u8;
            idx += 1;
        }
    }
    hash
}

/// `imageutil.thumbhashSourceDimension`.
pub const THUMBHASH_SOURCE_DIMENSION: usize = 100;

/// `imageutil.Thumbhash` for an already decoded NRGBA image: scaled, encoded, and standard base64.
pub fn thumbhash_nrgba(w: usize, h: usize, pix: &[u8]) -> String {
    let (dw, dh, scaled) = scale_image(w, h, pix, THUMBHASH_SOURCE_DIMENSION);
    std_encode(encode_nrgba(dw, dh, &scaled))
}
