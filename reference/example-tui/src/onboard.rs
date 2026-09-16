//! First-run TUI: the P-51 fly-in, then a fullscreen add-provider form.
//! Does not touch the daemon — onboarding has to start in a blink, which is
//! the lesson of this crate's first slice.
//!
//! Analog of `crates/cockpit-tui` banner art + the first-run provider wizard.

mod agent;
mod auth;
mod chrome;
mod clouds;
mod field;
mod form;
mod plane;
mod providers;
mod secrets;
mod titles;
mod verify;

use std::io::{self, IsTerminal, Stdout, Write};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{cursor, execute};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;

use clouds::{Cloud, Layer};
use plane::PropPhase;

const HINT: Color = Color::Rgb(0x8A, 0x9B, 0xB0);
const TITLE_SOLID: Color = Color::Rgb(0xF0, 0xF4, 0xF8);
const TITLE_SHADE: Color = Color::Rgb(0x9A, 0xA8, 0xB8);
const FRAME: Duration = Duration::from_millis(33);
const FLIGHT: Duration = Duration::from_millis(2400);
const TITLE_GAP: Duration = Duration::from_millis(380);
const PROMPT_GAP: Duration = Duration::from_secs(1);
const BOB_MS: u64 = 420;
/// Clear rows between the plane and the wordmarks, and between the two
/// wordmarks below it.
const TITLE_MARGIN: u16 = 1;
/// Clear rows between the bottom of the cockpit wordmark and the prompt.
const PROMPT_MARGIN: u16 = 3;

enum AnimationEnd {
    Continue,
    Quit,
}

pub fn run(skip_animation: bool) -> Result<()> {
    if !io::stdout().is_terminal() {
        bail!("excoc onboard needs a terminal (stdout is not a TTY)");
    }
    let summary = {
        let mut session = Session::enter()?;
        if !skip_animation {
            match session.play()? {
                AnimationEnd::Quit => return Ok(()),
                AnimationEnd::Continue => {}
            }
        }
        run_wizard(&mut session.terminal)?
    };
    summary.print();
    Ok(())
}

/// One provider carried all the way through auth and verification.
struct Added {
    provider: &'static providers::Provider,
    credential: String,
    verification: verify::Verification,
    /// Models the verify step confirmed, offered later to agent creation.
    models: Vec<verify::ModelEntry>,
}

/// What onboarding produced, echoed after the alternate screen is torn down.
struct Summary {
    encryption: Option<secrets::Encryption>,
    added: Vec<Added>,
    agent: Option<agent::AgentSummary>,
}

impl Summary {
    fn empty() -> Self {
        Self {
            encryption: None,
            added: Vec::new(),
            agent: None,
        }
    }

    fn print(&self) {
        match &self.encryption {
            Some(encryption) => println!("secrets: {}", encryption.summary()),
            None => {
                println!("onboarding canceled");
                return;
            }
        }
        if self.added.is_empty() {
            println!("no providers added");
            return;
        }
        for added in &self.added {
            println!(
                "{} ({}) · {} · {}",
                added.provider.display,
                added.provider.id,
                added.credential,
                added.verification.summary(),
            );
        }
        match &self.agent {
            Some(agent) => {
                for line in agent.lines() {
                    println!("{line}");
                }
            }
            None => println!("no agent created"),
        }
    }
}

/// Flatten every added provider's verified models into one agent-facing
/// catalog. Providers that publish no `/models` list still contribute a single
/// placeholder so the agent always has something to fly.
fn build_catalog(added: &[Added]) -> Vec<agent::AvailableModel> {
    let mut catalog = Vec::new();
    for entry in added {
        if entry.models.is_empty() {
            catalog.push(agent::AvailableModel {
                provider_id: entry.provider.id,
                provider_display: entry.provider.display,
                model_id: format!("{}-default", entry.provider.id),
                display: Some("default model".to_string()),
            });
        } else {
            for model in &entry.models {
                catalog.push(agent::AvailableModel {
                    provider_id: entry.provider.id,
                    provider_display: entry.provider.display,
                    model_id: model.id.clone(),
                    display: model.display.clone(),
                });
            }
        }
    }
    catalog
}

/// Walk the onboarding steps, honoring the per-step back button.
///
/// Secrets come first (the credentials are the first thing the vault holds),
/// then a repeatable provider loop: pick → authenticate → verify. Once the user
/// finishes adding providers, the agent-creation wizard runs over the models
/// they verified. Every step can step back to the one before it; stepping back
/// out of agent creation re-opens the picker to add another provider.
fn run_wizard(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<Summary> {
    let mut summary = Summary::empty();
    let mut resume_secrets: Option<secrets::Encryption> = None;

    'session: loop {
        let encryption = match secrets::run(terminal, resume_secrets.take())? {
            Some(encryption) => encryption,
            None => return Ok(summary),
        };
        summary.encryption = Some(encryption.clone());

        // Add providers until finished, then configure the first agent. Backing
        // out of agent creation drops us back here to add another provider.
        'build: loop {
            // Provider loop: each pass adds (or abandons) one provider.
            'providers: loop {
                let provider = match form::run(terminal)? {
                    form::Outcome::Chosen(provider) => provider,
                    // Back from the picker re-opens the secrets step.
                    form::Outcome::Back => {
                        resume_secrets = Some(encryption);
                        continue 'session;
                    }
                    form::Outcome::Quit => return Ok(summary),
                };

                // Auth and verify share a loop so "back" on verify re-runs auth
                // for the same provider without re-picking.
                'authverify: loop {
                    let credential = match auth::run(terminal, provider)? {
                        auth::Outcome::Ready(credential) => credential,
                        auth::Outcome::Back => continue 'providers, // back to the picker
                        auth::Outcome::Quit => return Ok(summary),
                    };

                    match verify::run(terminal, provider, &credential)? {
                        verify::Done::Next {
                            verification,
                            models,
                            add_another,
                        } => {
                            summary.added.push(Added {
                                provider,
                                credential: credential.summary(),
                                verification,
                                models,
                            });
                            if add_another {
                                continue 'providers;
                            }
                            break 'providers; // done adding → create the agent
                        }
                        verify::Done::Back => continue 'authverify, // back to auth
                        verify::Done::Quit => return Ok(summary),
                    }
                }
            }

            // At least one provider was added; build the model catalog and run
            // the agent-creation wizard over it.
            let catalog = build_catalog(&summary.added);
            match agent::run(terminal, &catalog)? {
                agent::Outcome::Created(created) => {
                    summary.agent = Some(created);
                    return Ok(summary);
                }
                // Step back into the provider flow to add another provider.
                agent::Outcome::Back => continue 'build,
                agent::Outcome::Quit => return Ok(summary),
            }
        }
    }
}

struct Session {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Session {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, cursor::Hide) {
            let _ = disable_raw_mode();
            return Err(error.into());
        }
        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
                let _ = disable_raw_mode();
                Err(error.into())
            }
        }
    }

    fn play(&mut self) -> Result<AnimationEnd> {
        let size = self.terminal.size()?;
        let mut scene = Scene::new(size.width, size.height);
        let started = Instant::now();
        let mut last = started;
        loop {
            let timeout = FRAME.saturating_sub(last.elapsed());
            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(key)
                        if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat =>
                    {
                        let ctrl_c = key.modifiers.contains(KeyModifiers::CONTROL)
                            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'));
                        let early_quit = !scene.prompt_visible()
                            && matches!(
                                key.code,
                                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q')
                            );
                        if ctrl_c || early_quit {
                            return Ok(AnimationEnd::Quit);
                        }
                        if scene.prompt_visible() {
                            return Ok(AnimationEnd::Continue);
                        }
                    }
                    Event::Resize(width, height) => scene.resize(width, height),
                    _ => {}
                }
            }
            let now = Instant::now();
            let dt = now.saturating_duration_since(last).as_secs_f64();
            last = now;
            scene.tick(dt, now.saturating_duration_since(started));
            self.terminal.draw(|frame| {
                let area = frame.area();
                scene.paint(frame.buffer_mut(), area);
            })?;
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            cursor::Show
        );
        let _ = self.terminal.show_cursor();
        let _ = io::stdout().flush();
    }
}

struct Scene {
    width: u16,
    height: u16,
    plane_x: f64,
    plane_y: u16,
    clouds: Vec<Cloud>,
    elapsed: Duration,
}

impl Scene {
    fn new(width: u16, height: u16) -> Self {
        let mut scene = Self {
            width,
            height,
            plane_x: 0.0,
            plane_y: 0,
            clouds: clouds::seed(width, height),
            elapsed: Duration::ZERO,
        };
        scene.layout();
        scene.plane_x = scene.start_x();
        scene
    }

    fn resize(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.clouds = clouds::seed(width, height);
        self.layout();
        self.sync_plane_x();
    }

    /// The plane flies through the vertical centre. When the wordmarks and
    /// prompt below it would not fit with their gaps, it flies higher — but
    /// never so high that welcome loses its row above.
    fn layout(&mut self) {
        let (_, plane_h) = plane::rendered_size();
        let centered = self.height.saturating_sub(plane_h) / 2;
        let above = titles::height(titles::WELCOME) + TITLE_MARGIN;
        let highest = if centered + plane_h + Self::stack_rows(TITLE_MARGIN) <= self.height {
            centered
        } else {
            self.height
                .saturating_sub(plane_h + Self::stack_rows(TITLE_MARGIN))
                .max(above)
        };
        self.plane_y = highest.min(centered);
    }

    /// Rows the stack below the plane needs: to, cockpit, and the prompt
    /// with its gap, using `margin` clear rows around to.
    fn stack_rows(margin: u16) -> u16 {
        margin
            + titles::height(titles::TO)
            + margin
            + titles::height(titles::COCKPIT)
            + PROMPT_MARGIN
            + 1
    }

    fn start_x(&self) -> f64 {
        let (plane_w, _) = plane::rendered_size();
        -f64::from(plane_w)
    }

    fn center_x(&self) -> f64 {
        let (plane_w, _) = plane::rendered_size();
        f64::from(self.width.saturating_sub(plane_w)) / 2.0
    }

    fn sync_plane_x(&mut self) {
        let t = flight_t(self.elapsed);
        self.plane_x = lerp(self.start_x(), self.center_x(), ease_out_cubic(t));
    }

    fn tick(&mut self, dt: f64, elapsed: Duration) {
        self.elapsed = elapsed;
        self.sync_plane_x();
        for cloud in &mut self.clouds {
            cloud.tick(dt, self.width);
        }
    }

    fn welcome_at() -> Duration {
        FLIGHT + TITLE_GAP
    }

    fn to_at() -> Duration {
        FLIGHT + TITLE_GAP + TITLE_GAP
    }

    fn cockpit_at() -> Duration {
        FLIGHT + TITLE_GAP + TITLE_GAP + TITLE_GAP
    }

    fn prompt_at() -> Duration {
        Self::cockpit_at() + PROMPT_GAP
    }

    fn welcome_visible(&self) -> bool {
        self.elapsed >= Self::welcome_at()
    }

    fn to_visible(&self) -> bool {
        self.elapsed >= Self::to_at()
    }

    fn cockpit_visible(&self) -> bool {
        self.elapsed >= Self::cockpit_at()
    }

    fn prompt_visible(&self) -> bool {
        self.elapsed >= Self::prompt_at()
    }

    fn bob_offset(&self) -> i32 {
        if self.elapsed < FLIGHT {
            return 0;
        }
        let beat = (self.elapsed.saturating_sub(FLIGHT).as_millis() as u64) / BOB_MS;
        // Rest, one row up, rest, one row down — two pixels peak to peak.
        match beat % 4 {
            0 => 0,
            1 => -1,
            2 => 0,
            _ => 1,
        }
    }

    fn plane_draw_y(&self) -> i32 {
        i32::from(self.plane_y) + self.bob_offset()
    }

    fn paint(&self, buf: &mut Buffer, area: Rect) {
        clear(buf, area);
        for layer in Layer::ALL {
            for cloud in self.clouds.iter().filter(|c| c.layer == layer) {
                blit_cloud(buf, area, cloud);
            }
        }
        let sprites = self.sprites(area);
        // Knock a halo out of the clouds around every sprite pixel so the
        // plane and the wordmarks stay legible over a passing cloud. Cells
        // are about twice as tall as they are wide, so the halo is two
        // columns by one row.
        for pixel in &sprites {
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
        for pixel in &sprites {
            put(buf, area, pixel.x, pixel.y, pixel.ch, pixel.fg, pixel.bg);
        }
    }

    /// Everything that paints in front of the clouds, in draw order.
    fn sprites(&self, area: Rect) -> Vec<Pixel> {
        let mut out = Vec::new();
        self.plane_pixels(&mut out);
        self.title_pixels(area, &mut out);
        out
    }

    fn plane_pixels(&self, out: &mut Vec<Pixel>) {
        let phase = PropPhase::from_elapsed_ms(self.elapsed.as_millis() as u64);
        let origin_x = self.plane_x.round() as i32;
        let origin_y = self.plane_draw_y();
        for (row_i, row) in plane::cells(phase).iter().enumerate() {
            for (col_i, cell) in row.iter().enumerate() {
                let Some((glyph, fg, bg)) = cell else {
                    continue;
                };
                out.push(Pixel {
                    x: origin_x + col_i as i32,
                    y: origin_y + row_i as i32,
                    ch: glyph.chars().next().unwrap_or(' '),
                    fg: Color::Indexed(*fg),
                    bg: bg.map(Color::Indexed).unwrap_or(Color::Reset),
                });
            }
        }
    }

    /// Wordmarks sit one clear row off the plane on either side: welcome
    /// above, then to and cockpit below with a clear row between, and the
    /// prompt three clear rows under cockpit. On a terminal too short for
    /// that, the gaps go first, then the prompt drops to the last row, and
    /// only then is a wordmark left out.
    fn title_pixels(&self, area: Rect, out: &mut Vec<Pixel>) {
        let plane_bottom = self.plane_y + plane::RENDERED_HEIGHT;
        let above_h = self.plane_y;
        let room = self.height.saturating_sub(plane_bottom);

        if self.welcome_visible() {
            let h = titles::height(titles::WELCOME);
            let margin = if above_h >= h + TITLE_MARGIN {
                TITLE_MARGIN
            } else {
                0
            };
            if above_h >= h {
                let y = self.plane_y - h - margin;
                ascii_pixels(area, titles::WELCOME, i32::from(y), out);
            }
        }

        let to_h = titles::height(titles::TO);
        let cockpit_h = titles::height(titles::COCKPIT);
        let show_to = self.to_visible();
        let show_cockpit = self.cockpit_visible();
        let margin = if Self::stack_rows(TITLE_MARGIN) <= room {
            TITLE_MARGIN
        } else {
            0
        };
        // With the gaps gone the prompt still needs the last row; only if
        // even that overflows does "to" give way to "cockpit".
        let both_fit = to_h + cockpit_h < room;
        let mut below_top = plane_bottom.saturating_add(margin);
        let mut stack_end = plane_bottom;

        if show_to && (!show_cockpit || both_fit) {
            ascii_pixels(area, titles::TO, i32::from(below_top), out);
            stack_end = below_top.saturating_add(to_h);
            below_top = stack_end.saturating_add(margin);
        }
        if show_cockpit {
            ascii_pixels(area, titles::COCKPIT, i32::from(below_top), out);
            stack_end = below_top.saturating_add(cockpit_h);
        }
        if self.prompt_visible() {
            let last_row = self.height.saturating_sub(1);
            let y = stack_end.saturating_add(PROMPT_MARGIN).min(last_row);
            centered_line_pixels(area, titles::PROMPT, i32::from(y), HINT, out);
        }
    }
}

/// One foreground cell, resolved to screen coordinates.
struct Pixel {
    x: i32,
    y: i32,
    ch: char,
    fg: Color,
    bg: Color,
}

fn flight_t(elapsed: Duration) -> f64 {
    (elapsed.as_secs_f64() / FLIGHT.as_secs_f64()).clamp(0.0, 1.0)
}

fn ease_out_cubic(t: f64) -> f64 {
    let u = 1.0 - t;
    1.0 - u * u * u
}

fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a + (b - a) * t
}

/// The scene has no backdrop of its own: every cell starts as the
/// terminal's default colours.
fn clear(buf: &mut Buffer, area: Rect) {
    for y in area.y..area.bottom() {
        for x in area.x..area.right() {
            let cell = &mut buf[(x, y)];
            cell.set_char(' ');
            cell.set_fg(Color::Reset);
            cell.set_bg(Color::Reset);
        }
    }
}

fn blit_cloud(buf: &mut Buffer, area: Rect, cloud: &Cloud) {
    let origin_x = cloud.x.round() as i32;
    let origin_y = i32::from(cloud.y);
    for (row_i, row) in cloud.cells.iter().enumerate() {
        for (col_i, pixel) in row.iter().enumerate() {
            let Some(pixel) = pixel else {
                continue;
            };
            put(
                buf,
                area,
                origin_x + col_i as i32,
                origin_y + row_i as i32,
                pixel.ch,
                pixel.fg,
                pixel.bg,
            );
        }
    }
}

/// Wordmark glyphs, plus clear cells for the gaps *between* glyphs on each
/// row so a cloud cannot show through the counters of the letters.
fn ascii_pixels(area: Rect, lines: &[&str], top: i32, out: &mut Vec<Pixel>) {
    let width = i32::from(titles::width(lines));
    let left = (i32::from(area.width) - width) / 2;
    for (row, line) in lines.iter().enumerate() {
        let inked: Vec<usize> = line
            .chars()
            .enumerate()
            .filter(|&(_, ch)| title_ink(ch).is_some())
            .map(|(col, _)| col)
            .collect();
        let (Some(&first), Some(&last)) = (inked.first(), inked.last()) else {
            continue;
        };
        for (col, ch) in line.chars().enumerate().take(last + 1).skip(first) {
            let fg = title_ink(ch).unwrap_or(Color::Reset);
            out.push(Pixel {
                x: left + col as i32,
                y: top + row as i32,
                ch,
                fg,
                bg: Color::Reset,
            });
        }
    }
}

fn centered_line_pixels(area: Rect, text: &str, y: i32, fg: Color, out: &mut Vec<Pixel>) {
    let width = text.chars().count() as i32;
    let left = (i32::from(area.width) - width) / 2;
    for (i, ch) in text.chars().enumerate() {
        out.push(Pixel {
            x: left + i as i32,
            y,
            ch,
            fg,
            bg: Color::Reset,
        });
    }
}

fn title_ink(ch: char) -> Option<Color> {
    match ch {
        ' ' => None,
        '░' => Some(TITLE_SHADE),
        _ => Some(TITLE_SOLID),
    }
}

fn put(buf: &mut Buffer, area: Rect, x: i32, y: i32, ch: char, fg: Color, bg: Color) {
    if x < i32::from(area.x) || y < i32::from(area.y) {
        return;
    }
    let x = x as u16;
    let y = y as u16;
    if x >= area.right() || y >= area.bottom() {
        return;
    }
    let cell = &mut buf[(x, y)];
    cell.set_char(ch);
    cell.set_fg(fg);
    cell.set_bg(bg);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell_symbol(buf: &Buffer, x: u16, y: u16) -> String {
        buf[(x, y)].symbol().to_string()
    }

    /// The plane is the only sprite painted in ANSI palette colours; clouds
    /// and wordmarks use RGB, so this singles out plane cells.
    fn is_plane_cell(buf: &Buffer, x: u16, y: u16) -> bool {
        matches!(buf[(x, y)].fg, Color::Indexed(_))
    }

    #[test]
    fn plane_starts_off_the_left_edge() {
        let scene = Scene::new(80, 24);
        let (plane_w, _) = plane::rendered_size();
        assert!(scene.plane_x <= -f64::from(plane_w) + 0.5);
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 24));
        scene.paint(&mut buf, Rect::new(0, 0, 80, 24));
        let occupied = (0..80u16)
            .filter(|&x| (0..24u16).any(|y| is_plane_cell(&buf, x, y)))
            .count();
        assert_eq!(occupied, 0, "nothing of the plane should be visible at t=0");
    }

    #[test]
    fn plane_arrives_at_center_after_the_flight() {
        let mut scene = Scene::new(80, 24);
        scene.tick(0.0, FLIGHT);
        let expected = scene.center_x();
        assert!((scene.plane_x - expected).abs() < 0.01);
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 24));
        scene.paint(&mut buf, Rect::new(0, 0, 80, 24));
        let (plane_w, plane_h) = plane::rendered_size();
        assert_eq!((plane_w, plane_h), (18, 6));
        let occupied = (0..80u16)
            .filter(|&x| {
                (scene.plane_y..scene.plane_y + plane_h)
                    .any(|y| y < 24 && is_plane_cell(&buf, x, y))
            })
            .count();
        assert!(
            occupied > 8,
            "centered banner-sized plane should be painted, got {occupied}"
        );
    }

    #[test]
    fn propeller_tops_toggle_between_phases() {
        let mut vertical = Scene::new(80, 24);
        vertical.tick(0.0, FLIGHT);
        let mut horizontal = Scene::new(80, 24);
        horizontal.tick(0.0, FLIGHT + Duration::from_millis(plane::PHASE_MS * 2));

        let v = plane::grid(PropPhase::from_elapsed_ms(
            vertical.elapsed.as_millis() as u64
        ));
        let h = plane::grid(PropPhase::from_elapsed_ms(
            horizontal.elapsed.as_millis() as u64
        ));
        assert_ne!(v[2].as_bytes()[34], b'.');
        assert_eq!(h[2].as_bytes()[34], b'.');
    }

    #[test]
    fn parallax_layers_keep_different_speeds() {
        let mut scene = Scene::new(80, 24);
        scene.tick(0.0, Duration::from_millis(100));
        assert!(
            scene
                .clouds
                .iter()
                .any(|c| c.layer == Layer::Far && c.speed.abs() < 12.0)
        );
        assert!(
            scene
                .clouds
                .iter()
                .any(|c| c.layer == Layer::Front && c.speed.abs() > 15.0)
        );
    }

    #[test]
    fn title_beats_follow_the_requested_gaps() {
        let mut scene = Scene::new(80, 40);
        scene.tick(0.0, FLIGHT);
        assert!(!scene.welcome_visible());
        assert!(!scene.prompt_visible());
        scene.tick(0.0, Scene::welcome_at());
        assert!(scene.welcome_visible());
        assert!(!scene.to_visible());
        scene.tick(0.0, Scene::to_at());
        assert!(scene.to_visible());
        assert!(!scene.cockpit_visible());
        scene.tick(0.0, Scene::cockpit_at());
        assert!(scene.cockpit_visible());
        assert!(!scene.prompt_visible());
        scene.tick(0.0, Scene::prompt_at());
        assert!(scene.prompt_visible());
        assert_eq!(Scene::welcome_at() - FLIGHT, TITLE_GAP);
        assert_eq!(Scene::to_at() - Scene::welcome_at(), TITLE_GAP);
        assert_eq!(Scene::cockpit_at() - Scene::to_at(), TITLE_GAP);
        assert_eq!(Scene::prompt_at() - Scene::cockpit_at(), PROMPT_GAP);
    }

    #[test]
    fn plane_bobs_two_pixels_peak_to_peak() {
        let mut scene = Scene::new(80, 24);
        scene.tick(0.0, FLIGHT);
        let rest = scene.plane_draw_y();
        assert_eq!(rest, i32::from(scene.plane_y));
        scene.tick(0.0, FLIGHT + Duration::from_millis(BOB_MS));
        let up = scene.plane_draw_y();
        scene.tick(0.0, FLIGHT + Duration::from_millis(BOB_MS * 2));
        let mid = scene.plane_draw_y();
        scene.tick(0.0, FLIGHT + Duration::from_millis(BOB_MS * 3));
        let down = scene.plane_draw_y();
        assert_eq!(up, rest - 1);
        assert_eq!(mid, rest);
        assert_eq!(down, rest + 1);
        assert_eq!(down - up, 2);
    }

    #[test]
    fn continue_prompt_is_absent_until_its_beat() {
        let mut scene = Scene::new(80, 24);
        scene.tick(0.0, Scene::cockpit_at());
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        scene.paint(&mut buf, area);
        let bottom = (0..80u16)
            .map(|x| cell_symbol(&buf, x, 23))
            .collect::<String>();
        assert!(
            !bottom.contains("continue"),
            "prompt must not appear before the 1s gap"
        );
        scene.tick(0.0, Scene::prompt_at());
        let mut buf = Buffer::empty(area);
        scene.paint(&mut buf, area);
        let bottom = (0..80u16)
            .map(|x| cell_symbol(&buf, x, 23))
            .collect::<String>();
        assert!(
            bottom.contains("continue"),
            "prompt should be on the continue row, got {bottom:?}"
        );
    }

    #[test]
    fn plane_flies_higher_when_the_stack_needs_room() {
        // 60 rows: everything fits around a centred plane.
        assert_eq!(Scene::new(80, 60).plane_y, 27);
        // 40 rows: the stack below needs 22 rows, so the plane moves up.
        assert_eq!(Scene::new(80, 40).plane_y, 12);
        // 24 rows: nothing fits anyway; the plane stays centred and welcome
        // keeps its rows above.
        assert_eq!(Scene::new(80, 24).plane_y, 9);
    }

    #[test]
    fn stack_below_the_plane_keeps_its_gaps() {
        let mut scene = Scene::new(80, 60);
        scene.tick(0.0, Scene::prompt_at());
        let area = Rect::new(0, 0, 80, 60);
        let mut buf = Buffer::empty(area);
        scene.paint(&mut buf, area);
        let row = |y: u16| {
            (0..80u16)
                .map(|x| cell_symbol(&buf, x, y))
                .collect::<String>()
        };
        let is_title = |y: u16| {
            (0..80u16).any(|x| matches!(buf[(x, y)].fg, c if c == TITLE_SOLID || c == TITLE_SHADE))
        };
        let plane_bottom = scene.plane_y + plane::RENDERED_HEIGHT;
        assert!(!is_title(plane_bottom), "clear row under the plane");
        assert!(is_title(plane_bottom + 1), "to starts one row below");
        let to_end = plane_bottom + 1 + titles::height(titles::TO);
        assert!(!is_title(to_end), "clear row between to and cockpit");
        assert!(is_title(to_end + 1), "cockpit starts after the gap");
        let cockpit_end = to_end + 1 + titles::height(titles::COCKPIT);
        for y in cockpit_end..cockpit_end + PROMPT_MARGIN {
            assert!(
                !row(y).contains("continue"),
                "row {y} should sit clear between cockpit and the prompt"
            );
        }
        assert!(row(cockpit_end + PROMPT_MARGIN).contains("continue"));
        assert!(!is_title(scene.plane_y - 1), "clear row above the plane");
        assert!(is_title(scene.plane_y - 2), "welcome ends above that");
    }

    #[test]
    fn ease_out_starts_fast_and_settles() {
        let early = ease_out_cubic(0.25);
        let mid = ease_out_cubic(0.5);
        let late = ease_out_cubic(0.9);
        assert!(early > 0.25, "cubic out covers distance early");
        assert!(
            late - mid < mid - early,
            "motion should decelerate into place"
        );
    }
}
