import { type FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { PageContainer } from "../components/layout/PageContainer";
import { Button } from "../components/ui/Button";
import { Card, CardBody } from "../components/ui/Card";
import { ErrorMessage } from "../components/ui/ErrorMessage";
import { SelectField, TextField } from "../components/ui/FormField";
import * as scanService from "../services/scanService";
import type { ScanConfig } from "../types/scan";

const initialConfig: ScanConfig = {
  target: "",
  portRange: "1-1024",
  scanType: "quick",
  scanDepth: "standard",
};

export function NewScan() {
  const navigate = useNavigate();
  const [config, setConfig] = useState<ScanConfig>(initialConfig);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  function updateField<K extends keyof ScanConfig>(key: K, value: ScanConfig[K]) {
    setConfig((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitError(null);

    const validationErrors = scanService.validateScanConfig(config);
    if (validationErrors.length > 0) {
      setFieldErrors(Object.fromEntries(validationErrors.map((e) => [e.field, e.message])));
      return;
    }
    setFieldErrors({});

    setIsSubmitting(true);
    try {
      const scan = await scanService.startScan(config);
      navigate(`/scans/${scan.id}/progress`);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Unable to start scan.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <PageContainer title="New Scan" description="Configure a target and launch a vulnerability scan.">
      <Card className="max-w-2xl">
        <CardBody>
          <form onSubmit={handleSubmit} className="flex flex-col gap-5" noValidate>
            <TextField
              label="Target IP / Hostname"
              placeholder="e.g. 10.0.1.12 or scanme.example.com"
              value={config.target}
              onChange={(e) => updateField("target", e.target.value)}
              error={fieldErrors.target}
              hint="Accepts an IPv4 address, CIDR range, or hostname."
            />

            <TextField
              label="Port Range"
              placeholder="e.g. 1-1024"
              value={config.portRange}
              onChange={(e) => updateField("portRange", e.target.value)}
              error={fieldErrors.portRange}
              hint="A single port (443) or a range (1-65535)."
            />

            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
              <SelectField
                label="Scan Type"
                value={config.scanType}
                onChange={(e) => updateField("scanType", e.target.value as ScanConfig["scanType"])}
                options={[
                  { value: "quick", label: "Quick — common ports only" },
                  { value: "full", label: "Full — all ports" },
                  { value: "custom", label: "Custom — use port range above" },
                ]}
              />

              <SelectField
                label="Scan Depth"
                value={config.scanDepth}
                onChange={(e) => updateField("scanDepth", e.target.value as ScanConfig["scanDepth"])}
                options={[
                  { value: "light", label: "Light — fast, fewer checks" },
                  { value: "standard", label: "Standard — balanced" },
                  { value: "deep", label: "Deep — thorough, slower" },
                ]}
              />
            </div>

            {submitError && <ErrorMessage title="Scan failed to start" message={submitError} />}

            <div className="flex items-center gap-3 pt-2">
              <Button type="submit" isLoading={isSubmitting}>
                Start Scan
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setConfig(initialConfig)}
                disabled={isSubmitting}
              >
                Reset
              </Button>
            </div>
            <p className="text-xs text-ink-500">
              Sprint 1 demo — this submits against mocked data. Sprint 2 wires this up to the real scan API.
            </p>
          </form>
        </CardBody>
      </Card>
    </PageContainer>
  );
}
