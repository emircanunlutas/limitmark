export function MethodologyDiagram() {
  return (
    <figure className="methodology-diagram" aria-label="Metodoloji: Kapsam, kontrollü yük, ölçüm ve bulgular">
      <div className="scope-boundary">
        <ol className="diagram-stages">
          {["Kapsam", "Kontrollü yük", "Ölçüm", "Bulgular"].map((stage) => <li key={stage}>{stage}</li>)}
        </ol>
      </div>
      <figcaption>Tanımlı test koşulları</figcaption>
    </figure>
  );
}
