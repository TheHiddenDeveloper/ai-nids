"use client";

import { Component } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: React.ReactNode;
  name: string;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center py-16 gap-4 text-center" role="alert">
          <AlertTriangle className="w-10 h-10 text-rose-400" />
          <div>
            <h3 className="text-lg font-semibold text-rose-300">{this.props.name} crashed</h3>
            <p className="text-sm text-slate-400 mt-1 max-w-md">
              {this.state.error?.message || "An unexpected error occurred."}
            </p>
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: undefined })}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium px-4 py-2 rounded-xl transition"
            aria-label={`Retry loading ${this.props.name}`}
          >
            <RefreshCw className="w-4 h-4" />
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
