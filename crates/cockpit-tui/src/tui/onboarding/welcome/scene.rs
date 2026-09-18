use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Color;

use super::clouds::{self, Layer};
use super::{plane, titles};

pub(crate) const FLIGHT_FRAMES: usize = 24;
const TITLE_GAP_FRAMES: usize = 4;
pub(crate) const PROMPT_GAP_FRAMES: usize = 10;
const WELCOME_FRAME: usize = FLIGHT_FRAMES + TITLE_GAP_FRAMES;
const TO_FRAME: usize = WELCOME_FRAME + TITLE_GAP_FRAMES;
pub(crate) const COCKPIT_FRAME: usize = TO_FRAME + TITLE_GAP_FRAMES;
pub(crate) const PROMPT_FRAME: usize = COCKPIT_FRAME + PROMPT_GAP_FRAMES;
const BOB_FRAMES: usize = 4;
const TITLE_MARGIN: u16 = 1;
const PROMPT_MARGIN: u16 = 3;
const TITLE_SOLID: Color = Color::Rgb(0xF0, 0xF4, 0xF8);
const TITLE_SHADE: Color = Color::Rgb(0x9A, 0xA8, 0xB8);
const HINT: Color = Color::Rgb(0x8A, 0x9B, 0xB0);

pub(crate) struct Scene {
    width: u16,
    height: u16,
    frame: usize,
    reduced_motion: bool,
    seed: u64,
    plane_y: u16,
}

impl Scene {
    pub(crate) fn new(
        width: u16,
        height: u16,
        frame: usize,
        reduced_motion: bool,
        seed: u64,
    ) -> Self {
        let mut scene = Self {
            width,
            height,
            frame,
            reduced_motion,
            seed,
            plane_y: 0,
        };
        scene.layout();
        scene
    }

    pub(crate) fn prompt_visible(&self) -> bool {
        self.reduced_motion || self.frame >= PROMPT_FRAME
    }

    pub(crate) fn plane_x(&self) -> f64 {
        let end = f64::from(self.width.saturating_sub(plane::WIDTH)) / 2.0;
        if self.reduced_motion {
            return end;
        }
        let start = -f64::from(plane::WIDTH);
        let t = (self.frame as f64 / FLIGHT_FRAMES as f64).clamp(0.0, 1.0);
        let eased = 1.0 - (1.0 - t).powi(3);
        start + (end - start) * eased
    }

    fn layout(&mut self) {
        let centered = self.height.saturating_sub(plane::HEIGHT) / 2;
        let stack = titles::TO.len() as u16
            + titles::COCKPIT.len() as u16
            + TITLE_MARGIN * 2
            + PROMPT_MARGIN
            + 1;
        let above = titles::WELCOME.len() as u16 + TITLE_MARGIN;
        let raised = self.height.saturating_sub(plane::HEIGHT + stack).max(above);
        self.plane_y = if centered + plane::HEIGHT + stack <= self.height {
            centered
        } else {
            raised.min(centered)
        };
    }

    fn bob_offset(&self) -> i32 {
        if self.reduced_motion || self.frame < FLIGHT_FRAMES {
            return 0;
        }
        match ((self.frame - FLIGHT_FRAMES) / BOB_FRAMES) % 4 {
            0 | 2 => 0,
            1 => -1,
            _ => 1,
        }
    }

    pub(crate) fn render(&self, frame: &mut Frame, area: Rect) {
        let buf = frame.buffer_mut();
        for y in area.y..area.bottom() {
            for x in area.x..area.right() {
                buf[(x, y)].reset();
            }
        }
        if !self.reduced_motion {
            for layer in Layer::ALL {
                for cloud in clouds::seed(self.width, self.height, self.seed)
                    .iter()
                    .filter(|cloud| cloud.layer == layer)
                {
                    let elapsed = self.frame as f64 / 10.0;
                    let x = drifted_x(cloud.x, cloud.speed, elapsed, self.width, cloud.width());
                    for (row, cells) in cloud.cells.iter().enumerate() {
                        for (col, pixel) in cells.iter().enumerate() {
                            if let Some(pixel) = pixel {
                                put(
                                    buf,
                                    area,
                                    x.round() as i32 + col as i32,
                                    i32::from(cloud.y) + row as i32,
                                    pixel.ch,
                                    pixel.fg,
                                    Color::Reset,
                                );
                            }
                        }
                    }
                }
            }
        }

        let mut foreground = Vec::new();
        self.plane_pixels(&mut foreground);
        self.title_pixels(area, &mut foreground);
        for pixel in &foreground {
            for dy in -1..=1 {
                for dx in -2..=2 {
                    put(
                        buf,
                        area,
                        pixel.x + dx,
                        pixel.y + dy,
                        ' ',
                        Color::Reset,
                        Color::Reset,
                    );
                }
            }
        }
        for pixel in foreground {
            put(buf, area, pixel.x, pixel.y, pixel.ch, pixel.fg, pixel.bg);
        }
    }

    fn plane_pixels(&self, out: &mut Vec<Pixel>) {
        let x = self.plane_x().round() as i32;
        let y = i32::from(self.plane_y) + self.bob_offset();
        for (row, cells) in plane::cells(self.frame).iter().enumerate() {
            for (col, cell) in cells.iter().enumerate() {
                if let Some((glyph, fg, bg)) = cell {
                    out.push(Pixel {
                        x: x + col as i32,
                        y: y + row as i32,
                        ch: glyph.chars().next().unwrap_or(' '),
                        fg: Color::Indexed(*fg),
                        bg: bg.map(Color::Indexed).unwrap_or(Color::Reset),
                    });
                }
            }
        }
    }

    fn title_pixels(&self, area: Rect, out: &mut Vec<Pixel>) {
        let landed = self.reduced_motion;
        if landed || self.frame >= WELCOME_FRAME {
            let h = titles::WELCOME.len() as u16;
            if self.plane_y >= h {
                let margin = u16::from(self.plane_y >= h + TITLE_MARGIN);
                ascii_pixels(
                    area,
                    titles::WELCOME,
                    i32::from(self.plane_y - h - margin),
                    out,
                );
            }
        }
        let plane_bottom = self.plane_y + plane::HEIGHT;
        let room = self.height.saturating_sub(plane_bottom);
        let margin = u16::from(
            room >= titles::TO.len() as u16
                + titles::COCKPIT.len() as u16
                + TITLE_MARGIN * 2
                + PROMPT_MARGIN
                + 1,
        );
        let mut y = plane_bottom + margin;
        let show_to = landed || self.frame >= TO_FRAME;
        let show_cockpit = landed || self.frame >= COCKPIT_FRAME;
        let both_fit = titles::TO.len() as u16 + (titles::COCKPIT.len() as u16) < room;
        let mut end = plane_bottom;
        if show_to && (!show_cockpit || both_fit) {
            ascii_pixels(area, titles::TO, i32::from(y), out);
            end = y + titles::TO.len() as u16;
            y = end + margin;
        }
        if show_cockpit {
            ascii_pixels(area, titles::COCKPIT, i32::from(y), out);
            end = y + titles::COCKPIT.len() as u16;
        }
        if self.prompt_visible() {
            let prompt_y = end
                .saturating_add(PROMPT_MARGIN)
                .min(self.height.saturating_sub(1));
            centered_line(area, titles::PROMPT, i32::from(prompt_y), HINT, out);
        }
    }
}

struct Pixel {
    x: i32,
    y: i32,
    ch: char,
    fg: Color,
    bg: Color,
}

/// Perpetual cloud drift position. The unwrapped position is preserved
/// until the cloud's right edge exits the left margin; past that the
/// cloud wraps to re-enter from the right edge, so the post-landing tick
/// never leaves an empty sky.
fn drifted_x(x: f64, speed: f64, elapsed: f64, width: u16, cloud_width: usize) -> f64 {
    let cloud_width = f64::from(cloud_width as u16);
    let span = f64::from(width) + cloud_width;
    (x + speed * elapsed + cloud_width).rem_euclid(span) - cloud_width
}

fn ascii_pixels(area: Rect, lines: &[&str], top: i32, out: &mut Vec<Pixel>) {
    let left = i32::from(area.x) + (i32::from(area.width) - i32::from(titles::width(lines))) / 2;
    for (row, line) in lines.iter().enumerate() {
        let ink: Vec<_> = line
            .chars()
            .enumerate()
            .filter(|(_, ch)| *ch != ' ')
            .map(|(i, _)| i)
            .collect();
        let (Some(first), Some(last)) = (ink.first(), ink.last()) else {
            continue;
        };
        for (col, ch) in line.chars().enumerate().take(last + 1).skip(*first) {
            let fg = if ch == '░' {
                TITLE_SHADE
            } else if ch == ' ' {
                Color::Reset
            } else {
                TITLE_SOLID
            };
            out.push(Pixel {
                x: left + col as i32,
                y: i32::from(area.y) + top + row as i32,
                ch,
                fg,
                bg: Color::Reset,
            });
        }
    }
}

fn centered_line(area: Rect, text: &str, y: i32, fg: Color, out: &mut Vec<Pixel>) {
    let left = i32::from(area.x) + (i32::from(area.width) - text.chars().count() as i32) / 2;
    for (col, ch) in text.chars().enumerate() {
        out.push(Pixel {
            x: left + col as i32,
            y: i32::from(area.y) + y,
            ch,
            fg,
            bg: Color::Reset,
        });
    }
}

fn put(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    x: i32,
    y: i32,
    ch: char,
    fg: Color,
    bg: Color,
) {
    if x < i32::from(area.x)
        || y < i32::from(area.y)
        || x >= i32::from(area.right())
        || y >= i32::from(area.bottom())
    {
        return;
    }
    let cell = &mut buf[(x as u16, y as u16)];
    cell.set_char(ch);
    cell.set_fg(fg);
    cell.set_bg(bg);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flight_x_is_monotonic() {
        let mut prior = Scene::new(80, 24, 0, false, 1).plane_x();
        for frame in 1..=FLIGHT_FRAMES {
            let x = Scene::new(80, 24, frame, false, 1).plane_x();
            assert!(x >= prior, "frame {frame}: {x} < {prior}");
            prior = x;
        }
    }

    #[test]
    fn bob_is_two_rows_peak_to_peak() {
        let offset = |frame| Scene::new(80, 24, frame, false, 1).bob_offset();
        assert_eq!(offset(FLIGHT_FRAMES), 0);
        assert_eq!(offset(FLIGHT_FRAMES + BOB_FRAMES), -1);
        assert_eq!(offset(FLIGHT_FRAMES + BOB_FRAMES * 3), 1);
    }

    #[test]
    fn prompt_observes_its_gap() {
        assert!(!Scene::new(80, 24, COCKPIT_FRAME, false, 1).prompt_visible());
        assert!(Scene::new(80, 24, PROMPT_FRAME, false, 1).prompt_visible());
        assert_eq!(PROMPT_FRAME - COCKPIT_FRAME, PROMPT_GAP_FRAMES);
    }

    #[test]
    fn reduced_motion_is_landed_with_no_bob() {
        let scene = Scene::new(80, 24, 0, true, 1);
        assert!(scene.prompt_visible());
        assert_eq!(scene.bob_offset(), 0);
    }

    #[test]
    fn cloud_drift_is_identity_until_exit_then_wraps() {
        // Still on screen: the unwrapped position is preserved exactly.
        assert_eq!(drifted_x(10.0, -2.0, 5.0, 80, 12), 0.0);
        assert_eq!(drifted_x(-11.0, -0.5, 1.0, 80, 12), -11.5);
        // Once the cloud exits the left edge it re-enters from the right
        // (left edge 72, cloud spans 72..84 on an 80-column sky), and the
        // wrap is periodic with the full drift span.
        assert_eq!(drifted_x(0.0, -2.0, 10.0, 80, 12), 72.0);
        assert_eq!(drifted_x(0.0, -2.0, 56.0, 80, 12), 72.0);
        // Wrapped positions always land inside [-cloud_width, width).
        for elapsed in [0, 7, 91, 500, 5_000] {
            let x = drifted_x(30.0, -20.0, f64::from(elapsed), 80, 24);
            assert!((-24.0..80.0).contains(&x), "elapsed {elapsed}: {x}");
        }
    }
}
