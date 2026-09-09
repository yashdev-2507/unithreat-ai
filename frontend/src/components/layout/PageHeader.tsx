import type { FC, ReactNode } from 'react';

export interface PageHeaderProps {
  title: string;
  description?: string;
  actions?: ReactNode;
}

export const PageHeader: FC<PageHeaderProps> = ({
  title,
  description,
  actions,
}) => {
  return (
    <div className="flex flex-col gap-1 pb-4 mb-6 border-b border-[var(--panel-border)] md:flex-row md:items-center md:justify-between">
      <div>
        <h1 className="text-xl font-bold tracking-tight text-slate-100 font-sans">
          {title}
        </h1>
        {description && (
          <p className="text-sm text-slate-400 font-sans mt-0.5">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="mt-3 md:mt-0 flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
};
