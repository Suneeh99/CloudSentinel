import type { ComponentPropsWithoutRef } from 'react';

type ButtonProps = ComponentPropsWithoutRef<'button'> & {
  variant?: 'primary' | 'secondary';
};

export function Button({ variant = 'secondary', className, ...props }: ButtonProps) {
  return (
    <button
      {...props}
      className={className ? `button ${className}` : 'button'}
      data-variant={variant}
    />
  );
}
