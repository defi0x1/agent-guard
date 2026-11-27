//! The Live and Alerts tabs: a table of events, newest first.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::level::Level;
use crate::top::app::App;
use crate::top::data;
use crate::top::ui::{level_span, selected_style};

/// Draws the events `ids` (newest first) as a table.
pub fn draw(f: &mut Frame, area: Rect, app: &App, ids: &[usize], title: &str) {
    let rows = ids.iter().filter_map(|&id| app.event(id)).map(|e| {
        let style = if data::bucket(e.level) == Level::Green {
            Style::default().add_modifier(Modifier::DIM)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(data::clock(e.ts, app.offset)),
            Cell::from(format!("{} {}", e.agent, data::short_session(&e.session))),
            Cell::from(data::kind(e)),
            Cell::from(e.target.clone()),
            Cell::from(Line::from(level_span(e.level, app.color))),
            Cell::from(e.rules.join(", ")),
        ])
        .style(style)
    });
    let widths = [
        Constraint::Length(8),
        Constraint::Length(16),
        Constraint::Length(7),
        Constraint::Fill(1),
        Constraint::Length(8),
        Constraint::Length(24),
    ];
    let mut title = title.to_string();
    if app.frozen.is_some() && title.contains("Live") {
        title.push_str("(paused) ");
    }
    let table = Table::new(rows, widths)
        .header(
            Row::new(["time", "agent", "kind", "target", "level", "rule"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(selected_style())
        .block(Block::default().borders(Borders::TOP).title(title));
    let mut state = TableState::default().with_selected(Some(app.selected(ids.len())));
    f.render_stateful_widget(table, area, &mut state);
}
