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
    <div className="flex flex-col gap-2 pb-4 mb-6 border-b border-[#E5E5E5] md:flex-row md:items-center md:justify-between">
      <div>
        <h1 className="text-2xl sm:text-[32px] font-bold tracking-tight text-[#0A0A0A] font-sans leading-tight">
          {title}
        </h1>
        {description && (
          <p className="text-sm sm:text-[15px] text-[#525252] font-sans mt-1.5 max-w-3xl leading-relaxed">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="mt-2 md:mt-0 flex flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  );
};
