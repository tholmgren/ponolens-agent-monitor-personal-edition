function cell(value) { const text = String(value ?? ""); return `"${text.replaceAll('"', '""')}"`; }
export function eventsCsv(events) {
  const rows = [["Event ID", "Observed at", "Harness", "Action", "Source", "Destination", "Severity", "Decision", "Summary", "Explanation"]];
  for (const event of events) rows.push([event.id, event.createdAt, event.harness, event.action, event.source, event.destination || "Local device", event.severity, event.decision, event.summary, event.explanation]);
  return `${rows.map((row) => row.map(cell).join(",")).join("\n")}\n`;
}

function pdfText(value) { return String(value ?? "").replace(/[^\x20-\x7E]/g, " ").replace(/([\\()])/g, "\\$1"); }
export function eventsPdf(events, title = "PonoLens Redacted Incident Report") {
  const lines = [title, `Generated: ${new Date().toISOString()}`, "Prompt content and detector samples are excluded.", ""];
  for (const event of events) {
    lines.push(`#${event.id} | ${event.createdAt} | ${event.harness} | ${event.decision.toUpperCase()}`);
    lines.push(String(event.summary || "").slice(0, 105));
    lines.push(`${event.source || "Local device"} -> ${event.destination || "Local device"}`.slice(0, 105), "");
  }
  const pages = []; for (let i = 0; i < lines.length; i += 52) pages.push(lines.slice(i, i + 52));
  const objects = [null, "<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"];
  const pageRefs = [];
  for (const page of pages) {
    const contentId = objects.length, pageId = contentId + 1; pageRefs.push(`${pageId} 0 R`);
    const stream = `BT /F1 9 Tf 40 750 Td 12 TL ${page.map((line) => `(${pdfText(line)}) Tj T*`).join(" ")} ET`;
    objects.push(`<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`);
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`);
  }
  objects[2] = `<< /Type /Pages /Kids [${pageRefs.join(" ")}] /Count ${pages.length} >>`;
  let output = "%PDF-1.4\n", offsets = [0];
  for (let id = 1; id < objects.length; id++) { offsets[id] = Buffer.byteLength(output); output += `${id} 0 obj\n${objects[id]}\nendobj\n`; }
  const xref = Buffer.byteLength(output); output += `xref\n0 ${objects.length}\n0000000000 65535 f \n${offsets.slice(1).map((offset) => `${String(offset).padStart(10, "0")} 00000 n `).join("\n")}\ntrailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(output, "ascii");
}
