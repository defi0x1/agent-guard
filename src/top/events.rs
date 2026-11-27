//! The Alerts and All calls tabs: one row per call, newest first, and a detail pane for the
//! selected call when the terminal is wide enough.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};

use crate::audit::{Event, clip};
use crate::level::Level;
use crate::top::app::App;
use crate::top::calls::{self, Call};
use crate::top::data;
use crate::top::ui::{chain, level_style, level_word, selected_style};

/// Narrower than this, the detail pane is left out.
pub const DETAIL_MIN: u16 = 110;
/// Narrower than this, the agent column is left out too.
pub const AGENT_MIN: u16 = 80;
const DETAIL_WIDTH: u16 = 44;

/// Draws the calls `rows` (newest first) as a list, with the selected one's detail beside it.
pub fn draw(f: &mut Frame, area: Rect, app: &App, rows: &[Call], title: &str) {
    let selected = app.selected(rows.len());
    let list = if area.width >= DETAIL_MIN {
        let [list, detail] =
            Layout::horizontal([Constraint::Fill(1), Constraint::Length(DETAIL_WIDTH)]).areas(area);
        draw_pane(f, detail, app, rows.get(selected));
        list
    } else {
        area
    };
    let with_agent = area.width >= AGENT_MIN;
    let mut fixed = vec![1, if app.relative { 4 } else { 8 }];
    if with_agent {
        fixed.push(10);
    }
    fixed.push(4);
    // Inside the borders, less the fixed columns and one space between each column.
    let rest = usize::from(list.width.saturating_sub(2))
        .saturating_sub(fixed.iter().sum::<usize>() + fixed.len() + 1);
    let what = rest / 2;
    let cols = Cols {
        with_agent,
        what,
        why: rest - what,
    };
    // Only the rows up to one screen below the selection are built; the table scrolls to it.
    let shown = selected + usize::from(list.height);
    let table_rows = rows.iter().take(shown).filter_map(|c| row(app, c, &cols));
    let mut widths: Vec<Constraint> = fixed
        .iter()
        .map(|&w| Constraint::Length(w as u16))
        .collect();
    let done = widths.pop();
    widths.extend([what, cols.why].map(|w| Constraint::Length(w as u16)));
    widths.extend(done);
    let mut title = title.to_string();
    if app.by_agent {
        title.push_str("by agent ");
    }
    let table = Table::new(table_rows, widths)
        .row_highlight_style(selected_style())
        .block(Block::default().borders(Borders::ALL).title(title));
    let mut state = TableState::default().with_selected(Some(selected));
    f.render_stateful_widget(table, list, &mut state);
}

/// The agent as shown: its name, or `└ <type>` for a subagent's call.
pub fn agent_label(e: &Event) -> String {
    match &e.agent_type {
        Some(t) => format!("└ {t}"),
        None => e.agent.clone(),
    }
}

/// The last column: how long the call took, `…` while it runs, `✗` when it was blocked.
fn done_mark(app: &App, c: &Call, first: &Event) -> String {
    if let Some(took) = c.took(|id| app.event(id).map(|e| e.ts)) {
        return calls::duration(took);
    }
    if first.source != "PreToolUse" {
        return String::new();
    }
    if c.level == Some(Level::HardBlock) {
        "✗".into()
    } else if c.ts + calls::MERGE_WINDOW > app.now {
        "…".into()
    } else {
        String::new()
    }
}

/// Which columns a row has, and how wide the two text columns are.
struct Cols {
    with_agent: bool,
    what: usize,
    why: usize,
}

fn row<'a>(app: &App, c: &Call, cols: &Cols) -> Option<Row<'a>> {
    let first = app.event(c.id)?;
    let main = app.event(c.main)?;
    let level = data::bucket(c.level);
    let tint = level_style(level, app.color);
    let (mark, why) = if level == Level::Green {
        (Span::raw("·"), Span::raw(""))
    } else {
        (
            Span::styled("●", tint.add_modifier(Modifier::BOLD)),
            Span::styled(clip(&calls::why(main), cols.why), tint),
        )
    };
    let time = if app.relative {
        data::ago(c.ts, app.now)
    } else {
        data::clock(c.ts, app.offset)
    };
    let mut cells = vec![Cell::from(mark), Cell::from(time)];
    if cols.with_agent {
        cells.push(Cell::from(clip(&agent_label(first), 10)));
    }
    cells.extend([
        Cell::from(clip(
            &format!("{} {}", calls::icon(first), calls::label(first)),
            cols.what,
        )),
        Cell::from(Line::from(why)),
        Cell::from(done_mark(app, c, first)),
    ]);
    let style = match app.fresh(c) {
        Some(0) if app.color => Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
        Some(0) => Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        Some(_) => Style::default().add_modifier(Modifier::BOLD),
        None if level == Level::Green => Style::default().add_modifier(Modifier::DIM),
        None => Style::default(),
    };
    Some(Row::new(cells).style(style))
}

/// The selected call in short: level and reason, what it did, the full message, the process,
/// the agent and session, the rule ids, and the keys that act on it.
fn draw_pane(f: &mut Frame, area: Rect, app: &App, call: Option<&Call>) {
    let block = Block::default().borders(Borders::ALL).title(" Detail ");
    let Some((c, first, main)) = call.and_then(|c| Some((c, app.event(c.id)?, app.event(c.main)?)))
    else {
        f.render_widget(Paragraph::new("Nothing selected.").block(block), area);
        return;
    };
    let level = data::bucket(c.level);
    let why = calls::why(main);
    let head = if why.is_empty() {
        "nothing found".to_string()
    } else {
        why
    };
    let dim = Style::default().add_modifier(Modifier::DIM);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{} ", level_word(c.level).to_uppercase()),
                level_style(level, app.color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(head.clone()),
        ]),
        Line::raw(format!("{} {}", calls::icon(first), calls::label(first))),
    ];
    let msg = calls::message(main);
    if !msg.is_empty() && msg.trim_end_matches('.') != head {
        lines.push(Line::raw(msg.to_string()));
    }
    lines.push(Line::raw(format!("process {}", chain(app, first))));
    let mut who = match &first.agent_type {
        Some(t) => format!("{} › {t}", first.agent),
        None => first.agent.clone(),
    };
    if !first.session.is_empty() {
        who.push_str(&format!(
            "  session {}",
            data::short_session(&first.session)
        ));
    }
    lines.push(Line::styled(who, dim));
    let mut rules: Vec<&str> = Vec::new();
    for r in first.rules.iter().chain(&main.rules) {
        if !rules.contains(&r.as_str()) {
            rules.push(r);
        }
    }
    if !rules.is_empty() {
        lines.push(Line::styled(format!("rules {}", rules.join(", ")), dim));
    }
    lines.push(Line::styled(
        format!(
            "{}  {}",
            data::clock(c.ts, app.offset),
            match done_mark(app, c, first).as_str() {
                "…" => "running".to_string(),
                "✗" => "blocked".to_string(),
                "" => String::new(),
                "✓" => "done".to_string(),
                d => format!("done in {d}"),
            }
        ),
        dim,
    ));
    lines.push(Line::raw(""));
    lines.push(Line::styled("t trust  b block  e explain  k kill", dim));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}
