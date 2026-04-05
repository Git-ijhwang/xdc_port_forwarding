use ratatui::{
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Table, Row},
    Terminal,
    backend::CrosstermBackend,
    Frame,
};
use std::io::Stdout;
// use tokio::io::Stdout;
// use std::io::{self, stdout};
use xdp_port_forwarding_common::{ForwardRule, InterfaceState};

pub fn render_ui (
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    iface_data: &[(u32, InterfaceState)],
    rules_data: &[(u16, ForwardRule)],
) -> std::io::Result<()>
{
    terminal.draw( |f: &mut Frame| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints( [
                    Constraint::Percentage(70),
                    Constraint::Percentage(30),
                ])
            .split(f.size());

        // Interface stats table
        let iface_rows: Vec<Row> = iface_data.iter()
            .map(|(id, stat)| Row::new(vec![
                id.to_string(),
                stat.rx_packets.to_string(),
                stat.rx_bytes.to_string(),
            ]))
            .collect();
        let iface_table = Table::new( iface_rows, [Constraint::Percentage(33); 3])
            .header(Row::new(vec![
                "IFIndex", "Packets", "Bytes"
            ]))
            .block(Block::default().borders(Borders::ALL).title("Interface State"));

        f.render_widget(iface_table, chunks[0]);

        //Forwarding Rule Table
        let rule_rows: Vec<Row> = rules_data.iter()
            .map(|(port, rule)| Row::new( vec! [
                port.to_string(),
                rule.packets.to_string(),
                ]))
            .collect();
        let rule_table = Table::new( rule_rows, [Constraint::Percentage(50); 2])
        .header(Row::new(vec![
            "Port", "Matched Packets"
        ]))
        .block(Block::default().borders(Borders::ALL).title("Forwarding Rules"));

        f.render_widget(rule_table, chunks[1]);
    })?;
    Ok(())
}