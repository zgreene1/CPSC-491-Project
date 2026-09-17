import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";

const fieldShell =
  "w-full rounded-lg border bg-ink-850 px-3 h-10 text-sm text-ink-100 placeholder:text-ink-400 " +
  "transition-[box-shadow,border-color] duration-150 " +
  "focus:outline-none focus-visible:ring-2 focus-visible:ring-signal-400 focus-visible:ring-offset-2 focus-visible:ring-offset-ink-950";

interface FieldWrapperProps {
  label: string;
  hint?: string;
  error?: string;
  htmlFor: string;
  children: ReactNode;
}

function FieldWrapper({ label, hint, error, htmlFor, children }: FieldWrapperProps) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-sm font-medium text-ink-200">
        {label}
      </label>
      {children}
      {error ? (
        <p className="text-sm text-severity-critical" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p className="text-sm text-ink-400">{hint}</p>
      ) : null}
    </div>
  );
}

interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
  error?: string;
}

export function TextField({ label, hint, error, id, className = "", ...rest }: TextFieldProps) {
  const generatedId = useId();
  const fieldId = id ?? generatedId;
  return (
    <FieldWrapper label={label} hint={hint} error={error} htmlFor={fieldId}>
      <input
        id={fieldId}
        className={`${fieldShell} ${error ? "border-severity-critical" : "border-ink-600 hover:border-ink-500"} ${className}`}
        aria-invalid={Boolean(error)}
        {...rest}
      />
    </FieldWrapper>
  );
}

interface SelectOption {
  value: string;
  label: string;
}

interface SelectFieldProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string;
  hint?: string;
  error?: string;
  options: SelectOption[];
}

export function SelectField({
  label,
  hint,
  error,
  options,
  id,
  className = "",
  ...rest
}: SelectFieldProps) {
  const generatedId = useId();
  const fieldId = id ?? generatedId;
  return (
    <FieldWrapper label={label} hint={hint} error={error} htmlFor={fieldId}>
      <select
        id={fieldId}
        className={`${fieldShell} ${error ? "border-severity-critical" : "border-ink-600 hover:border-ink-500"} ${className}`}
        aria-invalid={Boolean(error)}
        {...rest}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </FieldWrapper>
  );
}
