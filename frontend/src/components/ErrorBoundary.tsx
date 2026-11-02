import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

type Props = {
  name: string;
  children: ReactNode;
  fallback?: ReactNode;
};

type State = {
  hasError: boolean;
  error: Error | null;
};

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[ErrorBoundary/${this.props.name}]`, error, info.componentStack);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div className="flex items-center justify-center py-16">
          <div className="max-w-sm text-center">
            <AlertTriangle className="mx-auto h-8 w-8 text-destructive/70" />
            <h2 className="mt-3 text-mono ba-text-base text-foreground">
              {this.props.name} — crashed
            </h2>
            <p className="mt-1 ba-text-sm text-muted-foreground">
              {this.state.error?.message ?? "An unexpected error occurred."}
            </p>
            <button
              onClick={this.handleRetry}
              className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs text-primary transition-colors duration-150 hover:bg-primary/20"
            >
              $ retry
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
