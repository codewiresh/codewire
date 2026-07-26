import * as React from "react";

type ThemeProviderProps = {
  children: React.ReactNode;
  defaultTheme?: string;
  storageKey?: string;
};

export function ThemeProvider({ children }: ThemeProviderProps) {
  return <>{children}</>;
}
