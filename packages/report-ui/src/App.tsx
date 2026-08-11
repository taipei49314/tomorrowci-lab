import { useMemo, useState } from "react";
import type { ReportModel, ReportScenario } from "./model";

type Filter = "all" | "attention" | "pass";

function StatusBadge({ scenario }: { scenario: ReportScenario }) {
  return (
    <span className={`badge badge-${scenario.tone}`} aria-label={`verdict ${scenario.verdict}`}>
      {scenario.verdict}
    </span>
  );
}

function ScenarioCard({ scenario }: { scenario: ReportScenario }) {
  return (
    <li className="scenario-card" data-verdict={scenario.verdict}>
      <article aria-labelledby={`scenario-${scenario.order}`}>
        <div className="scenario-heading">
          <div>
            <p className="scenario-order">Scenario {scenario.order + 1}</p>
            <h3 id={`scenario-${scenario.order}`}>
              <code>{scenario.id}</code>
            </h3>
          </div>
          <StatusBadge scenario={scenario} />
        </div>
        <dl className="scenario-grid">
          <div>
            <dt>Role</dt>
            <dd>{scenario.isBaseline ? "Baseline" : "Candidate"}</dd>
          </div>
          <div>
            <dt>Runtime</dt>
            <dd>{scenario.runtime}</dd>
          </div>
          <div>
            <dt>Dependencies</dt>
            <dd>{scenario.dependencies}</dd>
          </div>
          <div>
            <dt>Changed axes</dt>
            <dd>{scenario.axesChanged.length > 0 ? scenario.axesChanged.join(", ") : "None"}</dd>
          </div>
          <div>
            <dt>Test attempts</dt>
            <dd>{scenario.testAttempts}</dd>
          </div>
          <div>
            <dt>Duration</dt>
            <dd>{scenario.durationMs === null ? "Not run" : `${scenario.durationMs} ms`}</dd>
          </div>
        </dl>
        {(scenario.image || scenario.imageDigest) && (
          <details>
            <summary>Container identity</summary>
            <dl className="identity-list">
              <div>
                <dt>Image</dt>
                <dd><code>{scenario.image ?? "Not recorded"}</code></dd>
              </div>
              <div>
                <dt>Digest</dt>
                <dd><code>{scenario.imageDigest ?? "Not recorded"}</code></dd>
              </div>
            </dl>
          </details>
        )}
        {scenario.failureSummary && (
          <p className="failure-summary">
            <strong>{scenario.failureKind ?? "Failure"}:</strong> {scenario.failureSummary}
          </p>
        )}
        <nav className="scenario-links" aria-label={`Evidence for ${scenario.id}`}>
          <a href={scenario.links.scenario}>Scenario</a>
          <a href={scenario.links.environment}>Environment</a>
          <a href={scenario.links.result}>Result</a>
          <a href={scenario.links.replayDescriptor}>Replay descriptor</a>
        </nav>
      </article>
    </li>
  );
}

function Denominator({ model }: { model: ReportModel }) {
  const values = [
    ["PASS", model.denominator.pass],
    ["FAIL", model.denominator.fail],
    ["FLAKY", model.denominator.flaky],
    ["BLOCKED", model.denominator.blocked],
    ["UNSUPPORTED", model.denominator.unsupported],
    ["INCONCLUSIVE", model.denominator.inconclusive],
    ["NOT_RUN", model.denominator.notRun],
  ] as const;
  return (
    <dl className="denominator" aria-label="Scenario denominator">
      {values.map(([label, count]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{count}</dd>
        </div>
      ))}
    </dl>
  );
}

export function App({ model }: { model: ReportModel }) {
  const [filter, setFilter] = useState<Filter>("all");
  const visible = useMemo(
    () =>
      model.scenarios.filter((scenario) => {
        if (filter === "pass") return scenario.verdict === "PASS";
        if (filter === "attention") return scenario.verdict !== "PASS";
        return true;
      }),
    [filter, model.scenarios],
  );

  return (
    <>
      <a className="skip-link" href="#main">Skip to main content</a>
      <header className="site-header">
        <div className="shell header-layout">
          <div>
            <p className="product-name">TomorrowCI</p>
            <p className="product-purpose">Continuous Integration Against the Future.</p>
          </div>
          <nav aria-label="Report sections">
            <a href="#frontier">Frontier</a>
            <a href="#scenarios">Scenarios</a>
            <a href="#replays">Replays</a>
            <a href="#evidence">Evidence</a>
          </nav>
        </div>
      </header>

      <main id="main" className="shell">
        <section className="run-intro" aria-labelledby="report-title">
          <div>
            <p className="model-version">Verified report model · {model.schemaVersion}</p>
            <h1 id="report-title">Run <code>{model.run.id}</code></h1>
            <p className="intro-copy">
              {model.run.ecosystem} evidence from <code>{model.run.source}</code>. The interface is a
              read-only projection and never upgrades a recorded verdict.
            </p>
          </div>
          <dl className="run-meta">
            <div><dt>Tool</dt><dd>{model.run.toolVersion}</dd></div>
            <div><dt>Evidence schema</dt><dd>{model.evidenceSchemaVersion}</dd></div>
            <div><dt>Commit</dt><dd><code>{model.run.commitSha ?? "Dirty or unavailable"}</code></dd></div>
            <div><dt>Started</dt><dd>{model.run.startedAt}</dd></div>
          </dl>
        </section>

        <section id="frontier" className="frontier" aria-labelledby="frontier-title">
          <div className="section-heading">
            <div>
              <p className="section-index">01</p>
              <h2 id="frontier-title">Breakage frontier</h2>
            </div>
            <span className={`authorization ${model.frontier.observed ? "authorized" : "not-authorized"}`}>
              {model.frontier.authorization === "AUTHORIZED_BY_VERIFIED_FRONTIER"
                ? "AUTHORIZED BY VERIFIED FRONTIER"
                : "NOT AUTHORIZED"}
            </span>
          </div>
          <div className="frontier-layout">
            <div>
              <p className="horizon-value">
                {model.frontier.observed ? model.frontier.horizonLabel ?? "Observed" : "No horizon observed"}
              </p>
              <p>
                Grade <strong>{model.frontier.grade}</strong>
                {model.frontier.changedAxes.length > 0
                  ? ` · changed ${model.frontier.changedAxes.join(", ")}`
                  : " · no changed axis recorded"}
              </p>
              {model.frontier.failureSummary && (
                <p className="failure-summary">
                  {model.frontier.failureSummary}
                  {model.frontier.failureHash && <> · <code>{model.frontier.failureHash}</code></>}
                </p>
              )}
              {model.frontier.replayCommand && (
                <p className="replay-command"><strong>Replay</strong> <code>{model.frontier.replayCommand}</code></p>
              )}
            </div>
            <dl className="baseline">
              <div><dt>Baseline runtime</dt><dd>{model.baseline.runtime}</dd></div>
              <div><dt>Baseline dependencies</dt><dd>{model.baseline.dependencies}</dd></div>
              <div><dt>Declared by</dt><dd>{model.baseline.declaredBy}</dd></div>
              <div><dt>First failing scenario</dt><dd><code>{model.frontier.firstFailingScenario ?? "None"}</code></dd></div>
            </dl>
          </div>
          {model.frontier.notes.length > 0 && (
            <ul className="notes" aria-label="Frontier notes">
              {model.frontier.notes.map((note, index) => <li key={index}>{note}</li>)}
            </ul>
          )}
        </section>

        <section id="scenarios" aria-labelledby="scenarios-title">
          <div className="section-heading">
            <div>
              <p className="section-index">02</p>
              <h2 id="scenarios-title">Scenario order</h2>
            </div>
            <p>{model.denominator.total} scenarios in the verified model</p>
          </div>
          <Denominator model={model} />
          <div className="filter-bar">
            <div className="filter-controls" role="group" aria-label="Filter scenarios">
              {(["all", "attention", "pass"] as const).map((value) => (
                <button
                  type="button"
                  key={value}
                  aria-pressed={filter === value}
                  onClick={() => setFilter(value)}
                >
                  {value === "all" ? "All" : value === "attention" ? "Needs attention" : "Pass only"}
                </button>
              ))}
            </div>
            <p className="result-count" aria-live="polite">Showing {visible.length} of {model.scenarios.length}</p>
          </div>
          <ol className="scenario-list">
            {visible.map((scenario) => <ScenarioCard key={`${scenario.order}-${scenario.id}`} scenario={scenario} />)}
          </ol>
        </section>

        <section id="replays" aria-labelledby="replays-title">
          <div className="section-heading">
            <div>
              <p className="section-index">03</p>
              <h2 id="replays-title">Replay attempts</h2>
            </div>
            <p>{model.replayAttempts.length} recorded</p>
          </div>
          {model.replayAttempts.length > 0 ? (
            <ol className="replay-list">
              {model.replayAttempts.map((attempt) => (
                <li key={`${attempt.scenarioId}-${attempt.attempt}`}>
                  <div><code>{attempt.scenarioId}</code><span>Attempt {attempt.attempt}</span></div>
                  <a href={attempt.resultHref}>Open result.json</a>
                </li>
              ))}
            </ol>
          ) : (
            <p className="empty-state">No canonical replay attempt directory was present when this report was generated.</p>
          )}
        </section>

        <section id="evidence" aria-labelledby="evidence-title">
          <div className="section-heading">
            <div>
              <p className="section-index">04</p>
              <h2 id="evidence-title">Evidence links</h2>
            </div>
          </div>
          <ul className="evidence-list">
            {model.evidenceLinks.map((link) => (
              <li key={link.href}>
                <a href={link.href}>{link.label}</a>
                <p>{link.description}</p>
              </li>
            ))}
          </ul>
        </section>
      </main>
      <footer className="site-footer">
        <div className="shell">
          Read-only projection of checksummed evidence. Regenerate with <code>tomorrowci report</code>.
        </div>
      </footer>
    </>
  );
}
