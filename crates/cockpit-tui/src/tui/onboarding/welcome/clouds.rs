use ratatui::style::Color;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Layer {
    Horizon,
    Far,
    Mid,
    Near,
    Front,
}

impl Layer {
    pub(super) const ALL: [Self; 5] =
        [Self::Horizon, Self::Far, Self::Mid, Self::Near, Self::Front];
    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Pixel {
    pub(super) ch: char,
    pub(super) fg: Color,
}

#[derive(Clone, Debug)]
pub(super) struct Cloud {
    pub(super) x: f64,
    pub(super) y: u16,
    pub(super) cells: Vec<Vec<Option<Pixel>>>,
    pub(super) speed: f64,
    pub(super) layer: Layer,
}

#[derive(Clone, Copy)]
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
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1_u64 << 53) as f64
    }
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.unit()
    }
}

impl Cloud {
    /// Rasterized width in columns (every row has the same length).
    pub(super) fn width(&self) -> usize {
        self.cells.first().map_or(0, Vec::len)
    }
}

pub(super) fn seed(width: u16, height: u16, seed: u64) -> Vec<Cloud> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::new();
    for layer in Layer::ALL {
        let depth = layer.index();
        let count = 2 + usize::from(depth >= 3);
        for _ in 0..count {
            let cloud_w = ((usize::from(width) * (10 + depth * 4) / 100).clamp(8, 34))
                + (rng.next() as usize % 5);
            let cloud_h = (2 + depth).min(usize::from(height.saturating_sub(1)).max(1));
            let cells = raster(cloud_w, cloud_h, depth, rng.next());
            let max_y = height.saturating_sub(cloud_h as u16).saturating_sub(1);
            out.push(Cloud {
                x: rng.range(-(cloud_w as f64), f64::from(width)),
                y: (rng.unit() * f64::from(max_y + 1)) as u16,
                cells,
                speed: -(1.25 * 2_f64.powi(depth as i32) * rng.range(0.8, 1.2)),
                layer,
            });
        }
    }
    out
}

fn raster(width: usize, height: usize, depth: usize, seed: u64) -> Vec<Vec<Option<Pixel>>> {
    let mut rng = Rng::new(seed);
    let centers: Vec<_> = (0..(3 + width / 14))
        .map(|i| {
            let n = 3 + width / 14;
            let x = width as f64 * (0.18 + 0.64 * i as f64 / (n - 1).max(1) as f64);
            (
                x + rng.range(-2.0, 2.0),
                rng.range(height as f64 * 0.35, height as f64 * 0.7),
                rng.range(2.5, width as f64 / 5.0),
            )
        })
        .collect();
    let t = depth as f64 / 4.0;
    let color = Color::Rgb(
        (78.0 + 177.0 * t) as u8,
        (94.0 + 156.0 * t) as u8,
        (118.0 + 122.0 * t) as u8,
    );
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| {
                    let inside = centers.iter().any(|(cx, cy, radius)| {
                        let dx = (x as f64 - cx) / radius;
                        let dy = (y as f64 - cy) / (height as f64 * 0.48).max(1.0);
                        dx * dx + dy * dy < 1.0
                    });
                    inside.then_some(Pixel {
                        ch: if y + 1 == height { '▄' } else { '█' },
                        fg: color,
                    })
                })
                .collect()
        })
        .collect()
}
