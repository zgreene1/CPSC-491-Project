import type { ReactNode } from "react";
import { Header } from "./Header";

interface PageContainerProps {
  title: string;
  description?: string;
  children: ReactNode;
}

export function PageContainer({ title, description, children }: PageContainerProps) {
  return (
    <>
      <Header title={title} description={description} />
      <div className="flex-1 space-y-6 px-6 py-6">{children}</div>
    </>
  );
}
