//! Three depth layers of clouds drawn with block glyphs on the terminal's
//! own background. Far wisps crawl, back clouds drift, front clouds sail
//! past — bigger, brighter and faster the nearer they are. Everything here
//! paints *behind* the plane and the wordmarks.
//!
//! Every sprite is unique: a seeded generator lays out a metaball field for
//! one of three shape families (cumulus, puff, wisp), then the field is
//! sampled twice per row and lit from the upper left. Each half-cell gets
//! its own colour through two-tone half blocks, so the silhouette resolves
//! at double the row resolution and the shading reads as volume: bright
//! crowns, shaded undersides, and soft folds where lobes meet. Starting
//! positions, heights and speeds are rolled from the clock, and when a cloud
//! leaves the screen it comes back after a random pause as a new cloud at a
//! new height and speed, so the sky rolls on for as long as anyone watches.

use ratatui::style::Color;

/// Depth layers, farthest first. Each layer is twice as fast as the one
/// behind it, and brighter and bigger, which is what sells the parallax.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    Horizon,
    Far,
    Mid,
    Near,
    Front,
}

impl Layer {
    /// Paint order: farthest first.
    pub const ALL: [Layer; 5] = [
        Layer::Horizon,
        Layer::Far,
        Layer::Mid,
        Layer::Near,
        Layer::Front,
    ];

    /// 0 at the horizon, 1 right in front of the plane.
    fn depth(self) -> f64 {
        self as usize as f64 / (Self::ALL.len() - 1) as f64
    }

    /// Base leftward speed in columns per second, doubling per layer.
    fn speed(self) -> f64 {
        HORIZON_SPEED * 2f64.powi(self as i32)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Cumulus,
    Puff,
    Wisp,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CloudPixel {
    pub ch: char,
    pub fg: Color,
    /// `Color::Reset` except for two-tone half blocks, where the lower half
    /// of the cell is painted through the background.
    pub bg: Color,
}

#[derive(Clone, Debug)]
pub struct Cloud {
    pub x: f64,
    pub y: u16,
    pub cells: Vec<Vec<Option<CloudPixel>>>,
    /// Columns per second, always negative (leftward).
    pub speed: f64,
    pub layer: Layer,
    rng: Rng,
    band: Band,
}

/// Where a layer's clouds may sit, how big they grow, how fast they move
/// and how long they wait off screen before coming round again. Every
/// value is re-rolled from the band each time a cloud wraps.
#[derive(Clone, Copy, Debug)]
struct Band {
    term_width: u16,
    term_height: u16,
    width: (usize, usize),
    height: (usize, usize),
    /// Leftward columns per second, as a positive range.
    speed: (f64, f64),
    /// Off-screen pause after wrapping, in screen widths.
    gap: (f64, f64),
}

/// Sprite size relative to the layer's normal band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scale {
    Normal,
    Double,
    Triple,
}

impl Cloud {
    pub fn width(&self) -> u16 {
        self.cells.first().map(|row| row.len() as u16).unwrap_or(0)
    }

    pub fn height(&self) -> u16 {
        self.cells.len() as u16
    }

    pub fn tick(&mut self, dt: f64, term_width: u16) {
        self.x += self.speed * dt;
        let width = f64::from(self.width());
        if self.x + width < 0.0 {
            self.reroll();
            let gap = self.rng.between(self.band.gap.0, self.band.gap.1);
            self.x = f64::from(term_width) + 2.0 + gap * f64::from(term_width);
        }
    }

    /// Spawn somewhere across (or just off) the screen, so the first frame
    /// already has a sky in progress rather than a queue at the right edge.
    fn spawn(layer: Layer, band: Band, variant: u64) -> Self {
        let mut cloud = Self {
            x: 0.0,
            y: 0,
            cells: Vec::new(),
            speed: -1.0,
            layer,
            rng: Rng::new(variant),
            band,
        };
        cloud.reroll();
        let width = f64::from(cloud.width());
        cloud.x = cloud
            .rng
            .between(-width, f64::from(band.term_width) + width * 0.5);
        cloud
    }

    /// A fresh sprite, height and speed, so the wrap is a new cloud.
    fn reroll(&mut self) {
        let band = self.band;
        let width = self
            .rng
            .between(band.width.0 as f64, band.width.1 as f64 + 0.99) as usize;
        let height =
            self.rng
                .between(band.height.0 as f64, band.height.1 as f64 + 0.99) as usize;
        let seed = self.rng.next();
        let kind = kind_for(self.layer, &mut self.rng);
        self.cells = raster(width, height, self.layer, kind, seed);
        let max_y = band
            .term_height
            .saturating_sub(self.height())
            .saturating_sub(1);
        self.y = (self.rng.next_f64() * f64::from(max_y + 1)) as u16;
        self.speed = -self.rng.between(band.speed.0, band.speed.1);
    }
}

/// xorshift64*: tiny, deterministic, and good enough for cloud shapes.
#[derive(Clone, Copy, Debug)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn between(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.next_f64()
    }

    fn chance(&mut self, p: f64) -> bool {
        self.next_f64() < p
    }
}

#[derive(Clone, Copy, Debug)]
struct Tint {
    lit: (f64, f64, f64),
    shadow: (f64, f64, f64),
}

// Sunlit crowns run faintly warm, shadowed undersides faintly cool, which
// is what makes a white cloud read as lit rather than flat. Farther layers
// fade toward the horizon tint.
const FRONT_TINT: Tint = Tint {
    lit: (0xFF as f64, 0xFA as f64, 0xF0 as f64),
    shadow: (0x82 as f64, 0x96 as f64, 0xB4 as f64),
};
const HORIZON_TINT: Tint = Tint {
    lit: (0x4E as f64, 0x5E as f64, 0x76 as f64),
    shadow: (0x24 as f64, 0x2E as f64, 0x40 as f64),
};

/// Leftward speed of the farthest layer in columns per second; each layer
/// nearer doubles it, and each cloud rolls its own within a band around
/// its layer's base.
const HORIZON_SPEED: f64 = 1.25;
/// Per-cloud speed spread around the layer base: never so wide that a far
/// cloud can outrun a near one.
const SPEED_SPREAD: (f64, f64) = (0.8, 1.25);

/// Field strength at which a sample counts as inside the cloud.
const SOLID: f64 = 0.25;
/// Metaball radii are given as the *visible* radius; the falloff crosses
/// [`SOLID`] at `sqrt(1 - sqrt(SOLID))` of the true radius, so scale up.
const RADIUS_SCALE: f64 = 1.415;
/// Light from the upper left, in physical units (a row is two columns).
const LIGHT: (f64, f64) = (-0.45, -0.89);
/// Brightness is quantised so neighbouring half-cells share a colour and
/// collapse into a full block where the shading is flat.
const SHADE_STEPS: f64 = 14.0;

struct Blob {
    cx: f64,
    cy: f64,
    rx: f64,
    ry: f64,
}

impl Blob {
    fn field(&self, px: f64, py: f64) -> f64 {
        let dx = (px - self.cx) / (self.rx * RADIUS_SCALE);
        let dy = (py - self.cy) / (self.ry * RADIUS_SCALE);
        let d2 = dx * dx + dy * dy;
        if d2 >= 1.0 {
            0.0
        } else {
            let t = 1.0 - d2;
            t * t
        }
    }
}

/// A cloud's field, in cell coordinates, cut flat below `base`.
struct Field {
    blobs: Vec<Blob>,
    base: f64,
}

impl Field {
    fn at(&self, px: f64, py: f64) -> f64 {
        if py > self.base {
            return 0.0;
        }
        self.blobs.iter().map(|blob| blob.field(px, py)).sum()
    }

    /// How lit the surface is at a point, from -1 (facing away from the
    /// light) to 1 (facing it). Uses the field's gradient as the normal.
    fn lit(&self, px: f64, py: f64) -> f64 {
        let (hx, hy) = (0.35, 0.18);
        let gx = (self.at(px + hx, py) - self.at(px - hx, py)) / (2.0 * hx);
        // Rows are twice as tall as columns are wide.
        let gy = (self.at(px, py + hy) - self.at(px, py - hy)) / (2.0 * hy) / 2.0;
        let len = (gx * gx + gy * gy).sqrt();
        if len < 1e-6 {
            return 0.35;
        }
        // The gradient points inward; the normal points out.
        let (nx, ny) = (-gx / len, -gy / len);
        nx * LIGHT.0 + ny * LIGHT.1
    }
}

/// Layers, sizes and head counts of the sky. Two front clouds are twice
/// the normal front size and one is three times it: the giants that roll
/// through now and then.
const ROSTER: [(Layer, Scale, usize); 7] = [
    (Layer::Horizon, Scale::Normal, 2),
    (Layer::Far, Scale::Normal, 2),
    (Layer::Mid, Scale::Normal, 2),
    (Layer::Near, Scale::Normal, 2),
    (Layer::Front, Scale::Normal, 2),
    (Layer::Front, Scale::Double, 2),
    (Layer::Front, Scale::Triple, 1),
];

/// A sky seeded from the clock, so every run starts differently.
pub fn seed(term_width: u16, term_height: u16) -> Vec<Cloud> {
    seed_with(term_width, term_height, entropy())
}

pub fn seed_with(term_width: u16, term_height: u16, entropy: u64) -> Vec<Cloud> {
    let mut rng = Rng::new(entropy);
    let mut clouds = Vec::new();
    for (layer, scale, count) in ROSTER {
        let band = band(layer, scale, term_width, term_height);
        for _ in 0..count {
            clouds.push(Cloud::spawn(layer, band, rng.next()));
        }
    }
    clouds
}

fn entropy() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5EED);
    nanos ^ u64::from(std::process::id()).rotate_left(32)
}

fn band(layer: Layer, scale: Scale, term_width: u16, term_height: u16) -> Band {
    let (tw, th) = (term_width as usize, term_height as usize);
    let cols = |pct: usize, lo: usize, hi: usize| (tw * pct / 100).clamp(lo, hi);
    let rows = |pct: usize, lo: usize, hi: usize| (th * pct / 100).clamp(lo, hi);
    let (width, height) = match layer {
        Layer::Horizon => ((cols(10, 8, 16), cols(18, 14, 26)), (2, 3)),
        Layer::Far => ((cols(12, 10, 18), cols(22, 16, 30)), (2, rows(9, 3, 4))),
        Layer::Mid => (
            (cols(14, 12, 22), cols(22, 18, 32)),
            (rows(9, 3, 4), rows(14, 4, 6)),
        ),
        Layer::Near => (
            (cols(18, 16, 28), cols(28, 24, 40)),
            (rows(13, 4, 6), rows(19, 6, 8)),
        ),
        Layer::Front => (
            (cols(24, 20, 34), cols(36, 28, 48)),
            (rows(18, 6, 8), rows(26, 8, 11)),
        ),
    };
    let base = layer.speed();
    let speed = (base * SPEED_SPREAD.0, base * SPEED_SPREAD.1);
    let gap = (0.1, 0.8);
    // Giants are a fixed multiple of the layer's largest normal sprite,
    // never taller than the terminal. They are the nearest things in the
    // sky, so they move fastest, and they wait longer between passes so
    // they arrive as an event rather than a wall.
    let (width, height, speed, gap) = match scale {
        Scale::Normal => (width, height, speed, gap),
        Scale::Double | Scale::Triple => {
            let factor = if scale == Scale::Double { 2 } else { 3 };
            let w = width.1 * factor;
            let h = (height.1 * factor).min(th.saturating_sub(2).max(1));
            let speed = (base * 1.3, base * 1.7);
            let gap = if scale == Scale::Double {
                (0.8, 2.0)
            } else {
                (1.5, 3.5)
            };
            ((w, w), (h, h), speed, gap)
        }
    };
    Band {
        term_width,
        term_height,
        width,
        height,
        speed,
        gap,
    }
}

fn kind_for(layer: Layer, rng: &mut Rng) -> Kind {
    let roll = rng.next_f64();
    // (cumulus, puff) odds; the rest are wisps. Distant layers are wispier.
    let (cumulus, puff) = match layer {
        Layer::Horizon => (0.0, 0.0),
        Layer::Far => (0.2, 0.3),
        Layer::Mid => (0.5, 0.3),
        Layer::Near => (0.6, 0.4),
        Layer::Front => (0.75, 0.25),
    };
    if roll < cumulus {
        Kind::Cumulus
    } else if roll < cumulus + puff {
        Kind::Puff
    } else {
        Kind::Wisp
    }
}

fn tint_for(layer: Layer) -> Tint {
    let t = layer.depth();
    let mix = |a: (f64, f64, f64), b: (f64, f64, f64)| {
        (
            a.0 + (b.0 - a.0) * t,
            a.1 + (b.1 - a.1) * t,
            a.2 + (b.2 - a.2) * t,
        )
    };
    Tint {
        lit: mix(HORIZON_TINT.lit, FRONT_TINT.lit),
        shadow: mix(HORIZON_TINT.shadow, FRONT_TINT.shadow),
    }
}

fn raster(
    width: usize,
    height: usize,
    layer: Layer,
    kind: Kind,
    seed: u64,
) -> Vec<Vec<Option<CloudPixel>>> {
    let tint = &tint_for(layer);
    let field = shape(width, height, kind, seed);
    let h = height as f64;
    let billow = Billow::new(seed);
    // Finer tone steps on big sprites, where banding would otherwise show.
    let steps = (h * 2.0).clamp(SHADE_STEPS, SHADE_STEPS * 3.0);

    // Colour of one half-cell sample, or None when it is outside.
    let sample = |px: f64, py: f64| -> Option<Color> {
        let f = field.at(px, py);
        if f < SOLID {
            return None;
        }
        let lit = field.lit(px, py).clamp(-1.0, 1.0);
        // Rim shading follows the light; deep inside the field flattens
        // toward a bright, faintly lit crown.
        let depth = ((f - SOLID) / 0.55).clamp(0.0, 1.0);
        let rim = 0.22 + 0.78 * (0.5 + 0.5 * lit);
        let core = 0.80 + 0.16 * lit;
        let mut b = rim + (core - rim) * depth;
        // Undersides sit in their own shadow; the interior billows softly.
        b *= 1.0 - 0.26 * (py / h).clamp(0.0, 1.0);
        b += billow.at(px, py) * depth;
        Some(shade(tint, quantise(b, steps)))
    };

    let mut cells = vec![vec![None; width]; height];
    for (y, row) in cells.iter_mut().enumerate() {
        for (x, cell) in row.iter_mut().enumerate() {
            let px = x as f64 + 0.5;
            let py = y as f64;
            let top = sample(px, py + 0.25);
            let bottom = sample(px, py + 0.75);
            *cell = match (top, bottom) {
                (Some(t), Some(b)) if t == b => Some(CloudPixel {
                    ch: '█',
                    fg: t,
                    bg: Color::Reset,
                }),
                (Some(t), Some(b)) => Some(CloudPixel {
                    ch: '▀',
                    fg: t,
                    bg: b,
                }),
                (Some(t), None) => Some(CloudPixel {
                    ch: '▀',
                    fg: t,
                    bg: Color::Reset,
                }),
                (None, Some(b)) => Some(CloudPixel {
                    ch: '▄',
                    fg: b,
                    bg: Color::Reset,
                }),
                (None, None) => None,
            };
        }
    }
    cells
}

/// Low-frequency mottling from a few seeded sine waves, so the interior of
/// a cloud has gentle billows instead of one flat tone.
struct Billow {
    phase: [f64; 3],
}

impl Billow {
    fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed ^ 0xB1_110D);
        Self {
            phase: [
                rng.between(0.0, std::f64::consts::TAU),
                rng.between(0.0, std::f64::consts::TAU),
                rng.between(0.0, std::f64::consts::TAU),
            ],
        }
    }

    /// Brightness offset in roughly ±0.07 at cell `(px, py)`. Scaled in
    /// cells, not in the sprite box, so a giant gets more billows rather
    /// than bigger ones.
    fn at(&self, px: f64, py: f64) -> f64 {
        let (u, v) = (px / 30.0, py / 8.0);
        let a = (u * 9.5 + v * 3.0 + self.phase[0]).sin();
        let b = (u * 4.2 - v * 7.5 + self.phase[1]).sin();
        let c = (u * 15.0 + v * 11.0 + self.phase[2]).sin();
        0.035 * a + 0.025 * b + 0.012 * c
    }
}

fn quantise(b: f64, steps: f64) -> f64 {
    (b.clamp(0.0, 1.0) * steps).round() / steps
}

fn shade(tint: &Tint, b: f64) -> Color {
    let mix = |lo: f64, hi: f64| (lo + (hi - lo) * b).round() as u8;
    Color::Rgb(
        mix(tint.shadow.0, tint.lit.0),
        mix(tint.shadow.1, tint.lit.1),
        mix(tint.shadow.2, tint.lit.2),
    )
}

/// Lay out the metaballs for one cloud. Coordinates are fractions of the
/// sprite box; radii are visible radii.
fn shape(width: usize, height: usize, kind: Kind, seed: u64) -> Field {
    let mut rng = Rng::new(seed);
    let w = width as f64;
    let h = height as f64;
    let blob = |cx: f64, cy: f64, rx: f64, ry: f64| Blob {
        cx: w * cx,
        cy: h * cy,
        rx: w * rx,
        ry: h * ry,
    };
    let mut blobs = Vec::new();
    let base = match kind {
        Kind::Cumulus => {
            // A wide body, a row of crowns with one dominant, tufts at the
            // ends when there is room.
            blobs.push(blob(
                0.50,
                0.68,
                rng.between(0.42, 0.47),
                rng.between(0.22, 0.26),
            ));
            // Wider clouds carry more crowns; a giant with three would be a
            // blob.
            let most = (width / 12).clamp(2, 9) as f64;
            let crowns = rng.between((most - 2.0).max(2.0), most + 0.99) as usize;
            let dominant = rng.between(0.0, crowns as f64) as usize;
            // More crowns spread wider and each one narrows, so a giant's
            // skyline is a ridge of separate puffs rather than one hump.
            let span = if crowns > 4 {
                rng.between(0.62, 0.76)
            } else {
                rng.between(0.52, 0.64)
            };
            let start = 0.5 - span / 2.0;
            let crown_rx = (span / crowns as f64 * 1.15).clamp(0.09, 0.19);
            for i in 0..crowns {
                let along = if crowns == 1 {
                    0.5
                } else {
                    start + span * i as f64 / (crowns - 1) as f64
                };
                let cx = (along + rng.between(-0.03, 0.03)).clamp(0.14, 0.86);
                // Crowns stay inside the box: centre no higher than radius.
                let (cy, rx, ry) = if i == dominant {
                    let ry = rng.between(0.30, 0.36);
                    (ry + rng.between(0.02, 0.06), (crown_rx * 1.3).max(0.14), ry)
                } else {
                    let ry = rng.between(0.20, 0.30);
                    (
                        ry + rng.between(0.10, 0.34),
                        crown_rx * rng.between(0.85, 1.15),
                        ry,
                    )
                };
                blobs.push(blob(cx, cy, rx, ry));
            }
            if rng.chance(0.7) {
                blobs.push(blob(
                    rng.between(0.10, 0.15),
                    rng.between(0.60, 0.68),
                    rng.between(0.09, 0.13),
                    rng.between(0.14, 0.19),
                ));
            }
            if rng.chance(0.7) {
                blobs.push(blob(
                    rng.between(0.85, 0.90),
                    rng.between(0.60, 0.70),
                    rng.between(0.08, 0.12),
                    rng.between(0.13, 0.18),
                ));
            }
            rng.between(0.84, 0.90)
        }
        Kind::Puff => {
            // Two or three rounded lobes leaning on each other, no hard base.
            let lobes = if rng.chance(0.5) { 2 } else { 3 };
            let big = rng.between(0.0, lobes as f64) as usize;
            for i in 0..lobes {
                let along = 0.24 + 0.52 * i as f64 / (lobes - 1) as f64;
                let cx = along + rng.between(-0.04, 0.04);
                let (cy, rx, ry) = if i == big {
                    let ry = rng.between(0.34, 0.40);
                    (ry + rng.between(0.06, 0.12), rng.between(0.26, 0.32), ry)
                } else {
                    let ry = rng.between(0.26, 0.32);
                    (ry + rng.between(0.24, 0.32), rng.between(0.19, 0.25), ry)
                };
                blobs.push(blob(cx, cy, rx, ry));
            }
            blobs.push(blob(0.50, 0.70, 0.40, 0.22));
            rng.between(0.90, 0.97)
        }
        Kind::Wisp => {
            // A long low streak with a few soft swells along the top and a
            // tapered tail on one side.
            let tail_left = rng.chance(0.5);
            let (cx, rx) = if tail_left {
                (0.56, 0.42)
            } else {
                (0.44, 0.42)
            };
            blobs.push(blob(cx, 0.60, rx, rng.between(0.24, 0.30)));
            blobs.push(blob(
                if tail_left { 0.14 } else { 0.86 },
                rng.between(0.62, 0.70),
                rng.between(0.16, 0.22),
                rng.between(0.12, 0.16),
            ));
            let swells = rng.between(2.0, 3.99) as usize;
            for i in 0..swells {
                let along = 0.28 + 0.44 * i as f64 / (swells - 1).max(1) as f64;
                let ry = rng.between(0.22, 0.30);
                blobs.push(blob(
                    along + rng.between(-0.04, 0.04),
                    ry + rng.between(0.14, 0.24),
                    rng.between(0.12, 0.18),
                    ry,
                ));
            }
            rng.between(0.82, 0.90)
        }
    };
    let base = h * base;
    fit_to_box(&mut blobs, w, base);
    Field { blobs, base }
}

/// Metaball edges can run a little past a blob's visible radius where two
/// overlap, so lobes are scaled and shifted to leave a clear column at
/// each side and a clear half row above. Otherwise the sprite box would
/// clip them into a hard vertical edge.
fn fit_to_box(blobs: &mut [Blob], w: f64, base: f64) {
    const REACH: f64 = 1.15;
    let left = blobs
        .iter()
        .map(|b| b.cx - b.rx * REACH)
        .fold(f64::MAX, f64::min);
    let right = blobs
        .iter()
        .map(|b| b.cx + b.rx * REACH)
        .fold(f64::MIN, f64::max);
    let (lo, hi) = (1.0, w - 1.0);
    if right > left && hi > lo {
        let sx = (hi - lo) / (right - left);
        for b in blobs.iter_mut() {
            b.cx = lo + (b.cx - left) * sx;
            b.rx *= sx;
        }
    }
    let top = blobs
        .iter()
        .map(|b| b.cy - b.ry * REACH)
        .fold(f64::MAX, f64::min);
    let clear = 0.3;
    if top < clear && base > clear {
        // Squash toward the base so the crowns clear the top row.
        let sy = (base - clear) / (base - top);
        for b in blobs.iter_mut() {
            b.cy = base - (base - b.cy) * sy;
            b.ry *= sy;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid_count(cells: &[Vec<Option<CloudPixel>>], y: usize) -> usize {
        cells[y]
            .iter()
            .filter(
                |c| matches!(c, Some(p) if p.ch == '█' || (p.ch == '▀' && p.bg != Color::Reset)),
            )
            .count()
    }

    fn by_layer(clouds: &[Cloud], layer: Layer) -> Vec<&Cloud> {
        clouds.iter().filter(|c| c.layer == layer).collect()
    }

    #[test]
    fn every_layer_outruns_and_outgrows_the_one_behind_it() {
        let clouds = seed_with(120, 40, 1);
        for pair in Layer::ALL.windows(2) {
            let (behind, ahead) = (pair[0], pair[1]);
            let behind_clouds = by_layer(&clouds, behind);
            let ahead_clouds = by_layer(&clouds, ahead);
            assert!(!behind_clouds.is_empty() && !ahead_clouds.is_empty());
            let fastest_behind = behind_clouds
                .iter()
                .map(|c| c.speed.abs())
                .fold(0.0, f64::max);
            let slowest_ahead = ahead_clouds
                .iter()
                .map(|c| c.speed.abs())
                .fold(f64::MAX, f64::min);
            assert!(
                slowest_ahead > fastest_behind,
                "{ahead:?} ({slowest_ahead}) should outrun {behind:?} ({fastest_behind})"
            );
            let behind_band = band(behind, Scale::Normal, 120, 40);
            let ahead_band = band(ahead, Scale::Normal, 120, 40);
            assert!(
                ahead_band.height.1 >= behind_band.height.1
                    && ahead_band.width.1 >= behind_band.width.1,
                "{ahead:?} grows at least as large as {behind:?}"
            );
        }
        // Doubling per layer is what makes the parallax legible.
        assert_eq!(Layer::Front.speed(), Layer::Horizon.speed() * 16.0);
    }

    #[test]
    fn sprites_never_touch_their_box_edges() {
        for kind in [Kind::Cumulus, Kind::Puff, Kind::Wisp] {
            for (width, height) in [
                (12, 2),
                (18, 3),
                (24, 5),
                (36, 8),
                (48, 11),
                (96, 22),
                (144, 33),
            ] {
                for seed in 0..40 {
                    let cells = raster(width, height, Layer::Front, kind, seed);
                    let column_hit = |x: usize| cells.iter().any(|row| row[x].is_some());
                    assert!(
                        !column_hit(0) && !column_hit(width - 1),
                        "{kind:?} {width}x{height} seed {seed} runs into a side of its box"
                    );
                    let top_solid = cells[0].iter().any(|c| matches!(c, Some(p) if p.ch != '▄'));
                    assert!(
                        !top_solid,
                        "{kind:?} {width}x{height} seed {seed} is cut flat by the top of its box"
                    );
                }
            }
        }
    }

    #[test]
    fn giants_are_two_and_three_times_the_largest_normal_cloud() {
        let clouds = seed_with(120, 40, 3);
        let normal = band(Layer::Front, Scale::Normal, 120, 40);
        let (max_w, max_h) = (normal.width.1 as u16, normal.height.1 as u16);
        let doubles: Vec<_> = clouds
            .iter()
            .filter(|c| c.width() == max_w * 2 && c.height() == max_h * 2)
            .collect();
        let triples: Vec<_> = clouds
            .iter()
            .filter(|c| c.width() == max_w * 3 && c.height() == max_h * 3)
            .collect();
        assert_eq!(doubles.len(), 2, "two clouds at twice the largest size");
        let fastest_normal = clouds
            .iter()
            .filter(|c| c.height() <= max_h)
            .map(|c| c.speed.abs())
            .fold(0.0, f64::max);
        assert!(
            doubles
                .iter()
                .chain(&triples)
                .all(|c| c.speed.abs() > fastest_normal),
            "giants are nearest, so fastest"
        );
        assert_eq!(
            triples.len(),
            1,
            "one cloud at three times the largest size"
        );
        assert!(triples[0].height() < 40, "giant fits the terminal");
        // The giant keeps its size and layer after it wraps.
        let mut giant = triples[0].clone();
        giant.x = -(f64::from(giant.width()) + 1.0);
        giant.tick(0.05, 120);
        assert_eq!((giant.width(), giant.height()), (max_w * 3, max_h * 3));
        assert_eq!(giant.layer, Layer::Front);
    }

    #[test]
    fn giants_never_outgrow_a_short_terminal() {
        let clouds = seed_with(80, 24, 9);
        assert!(clouds.iter().all(|c| c.height() + c.y < 24));
        assert!(clouds.iter().all(|c| c.height() <= 22));
    }

    #[test]
    fn starts_and_speeds_are_randomised_per_run() {
        let a = seed_with(120, 40, 11);
        let b = seed_with(120, 40, 12);
        assert_eq!(a.len(), b.len());
        let xs_differ = a.iter().zip(&b).any(|(p, q)| p.x != q.x);
        let ys_differ = a.iter().zip(&b).any(|(p, q)| p.y != q.y);
        let speeds_differ = a.iter().zip(&b).any(|(p, q)| p.speed != q.speed);
        assert!(xs_differ && ys_differ && speeds_differ);
        // Starts are spread across the screen, not queued at one edge.
        let on_screen = a
            .iter()
            .filter(|c| c.x < 120.0 && c.x + f64::from(c.width()) > 0.0)
            .count();
        assert!(
            on_screen >= a.len() / 2,
            "{on_screen} of {} visible",
            a.len()
        );
        // Within a layer, speeds vary but stay inside the band.
        let front = by_layer(&a, Layer::Front);
        let speeds: Vec<f64> = front.iter().map(|c| c.speed.abs()).collect();
        assert!(speeds.iter().any(|s| (s - speeds[0]).abs() > 0.01));
        assert!(
            speeds
                .iter()
                .all(|&s| s >= Layer::Front.speed() * SPEED_SPREAD.0 - 1e-9)
        );
    }

    #[test]
    fn wrapping_reenters_after_a_pause_as_a_new_cloud() {
        let mut cloud = seed_with(80, 24, 5)
            .into_iter()
            .next()
            .expect("seeded clouds");
        let before = cloud.cells.clone();
        let speed_before = cloud.speed;
        cloud.x = -(f64::from(cloud.width()) + 1.0);
        cloud.tick(0.05, 80);
        assert!(cloud.x > 80.0, "wrapped cloud starts off the right edge");
        assert!(
            cloud.x <= 80.0 + 2.0 + 0.8 * 80.0 + 1e-9,
            "but not absurdly far"
        );
        assert!(cloud.height() + cloud.y < 80, "stays on screen");
        assert!(
            cloud.cells != before || cloud.speed != speed_before,
            "reroll changes the cloud"
        );
    }

    #[test]
    fn the_flow_never_runs_dry() {
        // Simulate a long watch: after every simulated minute, something is
        // still crossing the screen, and every cloud is still moving.
        let mut clouds = seed_with(120, 40, 21);
        let dt = 1.0 / 30.0;
        for minute in 1..=30 {
            for _ in 0..(60.0 / dt) as usize {
                for cloud in &mut clouds {
                    cloud.tick(dt, 120);
                }
            }
            let visible = clouds
                .iter()
                .filter(|c| c.x < 120.0 && c.x + f64::from(c.width()) > 0.0)
                .count();
            assert!(visible > 0, "sky empty after {minute} minutes");
            assert!(clouds.iter().all(|c| c.speed < 0.0 && c.x.is_finite()));
        }
    }

    #[test]
    fn variants_differ_and_are_deterministic() {
        let a = raster(36, 8, Layer::Front, Kind::Cumulus, 1);
        let b = raster(36, 8, Layer::Front, Kind::Cumulus, 2);
        let a_again = raster(36, 8, Layer::Front, Kind::Cumulus, 1);
        assert_eq!(a, a_again);
        assert_ne!(a, b, "different seeds must give different clouds");
    }

    #[test]
    fn cumulus_has_a_lit_crown_and_shaded_base() {
        let cells = raster(40, 9, Layer::Front, Kind::Cumulus, 7);
        assert!(
            solid_count(&cells, 4) > solid_count(&cells, 0),
            "body widens below the crowns"
        );
        let brightness = |c: &Option<CloudPixel>| match c {
            Some(CloudPixel {
                fg: Color::Rgb(r, g, b),
                ..
            }) => Some(u32::from(*r) + u32::from(*g) + u32::from(*b)),
            _ => None,
        };
        let top: Vec<u32> = cells[1].iter().filter_map(brightness).collect();
        let bottom: Vec<u32> = cells[cells.len() - 2]
            .iter()
            .filter_map(brightness)
            .collect();
        assert!(!top.is_empty() && !bottom.is_empty());
        let mean = |v: &[u32]| v.iter().sum::<u32>() as f64 / v.len() as f64;
        assert!(
            mean(&top) > mean(&bottom),
            "the crown is lit, the underside shaded"
        );
        let half_blocks = cells
            .iter()
            .flatten()
            .flatten()
            .filter(|p| p.ch == '▀' || p.ch == '▄')
            .count();
        assert!(half_blocks > 0, "edges resolve to half blocks");
    }

    #[test]
    fn giant_cumulus_grows_more_crowns() {
        let small = shape(30, 8, Kind::Cumulus, 4);
        let giant = shape(130, 30, Kind::Cumulus, 4);
        assert!(giant.blobs.len() > small.blobs.len());
    }

    #[test]
    fn wisps_are_low_and_puffs_have_no_flat_base() {
        let wisp = shape(24, 3, Kind::Wisp, 3);
        assert!(wisp.base < 3.0);
        let puff = shape(24, 6, Kind::Puff, 3);
        assert!(puff.base >= 6.0 * 0.90);
    }
}
