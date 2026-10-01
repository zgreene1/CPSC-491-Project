import { useState } from "react";
import { PageContainer } from "../components/layout/PageContainer";
import { Button } from "../components/ui/Button";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { SelectField, TextField } from "../components/ui/FormField";
import { useAuth } from "../context/AuthContext";

export function Settings() {
  const { user } = useAuth();
  const [displayName, setDisplayName] = useState(user?.displayName ?? "");
  const [notifyLevel, setNotifyLevel] = useState("critical-only");
  const [saved, setSaved] = useState(false);

  function handleSave() {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <PageContainer title="Settings" description="Manage your profile and scan notification preferences.">
      <Card className="max-w-xl">
        <CardHeader>
          <h2 className="font-[Space_Grotesk] text-base font-semibold text-ink-50">Profile</h2>
        </CardHeader>
        <CardBody className="flex flex-col gap-4">
          <TextField label="Display Name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          <TextField label="Username" value={user?.username ?? ""} disabled hint="Managed by your organization." />
          <SelectField
            label="Scan Alert Notifications"
            value={notifyLevel}
            onChange={(e) => setNotifyLevel(e.target.value)}
            options={[
              { value: "all", label: "Notify on all findings" },
              { value: "critical-only", label: "Critical and high only" },
              { value: "none", label: "Do not notify" },
            ]}
          />
          <div className="flex items-center gap-3 pt-2">
            <Button onClick={handleSave}>Save changes</Button>
            {saved && <span className="text-sm text-signal-400">Saved.</span>}
          </div>
        </CardBody>
      </Card>
    </PageContainer>
  );
}
