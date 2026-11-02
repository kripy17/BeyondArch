import { toast } from "sonner";

export type NotifyOptions = {
  description?: string;
  duration?: number;
};

export const notify = {
  success(message: string, opts?: NotifyOptions) {
    toast.success(message, { description: opts?.description, duration: opts?.duration ?? 3000 });
  },
  error(message: string, opts?: NotifyOptions) {
    toast.error(message, { description: opts?.description, duration: opts?.duration ?? 6000 });
  },
  warning(message: string, opts?: NotifyOptions) {
    toast.warning(message, { description: opts?.description, duration: opts?.duration ?? 4000 });
  },
  info(message: string, opts?: NotifyOptions) {
    toast(message, { description: opts?.description, duration: opts?.duration ?? 3000 });
  },
};
