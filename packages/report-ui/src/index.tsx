import { createRoot } from "react-dom/client";
import { App } from "./App";
import { parseReportModel } from "./model";
import "./report.css";

const rootElement = document.getElementById("report-root");
const dataElement = document.getElementById("report-data");

if (rootElement && dataElement) {
  try {
    const model = parseReportModel(JSON.parse(dataElement.textContent ?? ""));
    createRoot(rootElement).render(<App model={model} />);
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown report model error";
    createRoot(rootElement).render(
      <main className="shell interactive-error" role="alert">
        <h1>Interactive report unavailable</h1>
        <p>{message}</p>
        <p>Use the no-JavaScript fallback or inspect <a href="report.json">report.json</a>.</p>
      </main>,
    );
  }
}
