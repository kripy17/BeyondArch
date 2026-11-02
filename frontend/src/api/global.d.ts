declare module "@/api/backend" {
  export const safeAnalyzeUrl: (payload: Record<string, unknown>) => Promise<Record<string, unknown>>;
  export const parseLogs: (text: string) => Promise<Record<string, unknown>>;
  export const analyzeFullEmail: (headers: string, body: string, refangFirst?: boolean) => Promise<Record<string, unknown>>;
  export const analyzeSiemText: (text: string) => Promise<Record<string, unknown>>;
  export const uploadMalwareFile: (file: File) => Promise<Record<string, unknown>>;
}
declare module "@/api/detection" {
  export const mapMitre: (text: string) => Promise<Record<string, unknown>>;
  export const generateSigmaRule: (title: string, description: string, severity: string, logsourceType: string | null) => Promise<Record<string, unknown>>;
  export const getIdsRuleTemplates: () => Promise<Record<string, unknown>>;
  export const buildIdsRule: (payload: Record<string, unknown>) => Promise<Record<string, unknown>>;
  export const explainIdsRule: (rule: string) => Promise<Record<string, unknown>>;
}
