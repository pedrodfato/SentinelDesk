// The techniques this system can attribute, mirroring backend/report.py TECHNIQUES.
// Reference data, so a finding can show a name next to the bare id.
export const TECHNIQUE_NAMES: Record<string, string> = {
  "T1110.001": "Brute Force: Password Guessing",
  T1078: "Valid Accounts",
  "T1548.003": "Abuse Elevation Control: Sudo",
  "T1053.003": "Scheduled Task/Job: Cron",
};
