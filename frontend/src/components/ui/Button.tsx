import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
  children: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  icon,
  children,
  style,
  disabled,
  ...props
}) => {
  const sizeStyles = {
    sm: { padding: '6px 12px', fontSize: '0.8rem' },
    md: { padding: '8px 16px', fontSize: '0.875rem' },
    lg: { padding: '10px 20px', fontSize: '1rem' },
  }[size];

  const variantStyles = {
    primary: {
      background: 'linear-gradient(135deg, #0284c7 0%, #2563eb 100%)',
      color: '#ffffff',
      border: '1px solid rgba(56, 189, 248, 0.4)',
    },
    secondary: {
      background: 'rgba(30, 41, 59, 0.8)',
      color: '#f8fafc',
      border: '1px solid var(--border-color)',
    },
    outline: {
      background: 'transparent',
      color: '#38bdf8',
      border: '1px solid rgba(56, 189, 248, 0.5)',
    },
    danger: {
      background: 'rgba(244, 63, 94, 0.2)',
      color: '#fb7185',
      border: '1px solid rgba(244, 63, 94, 0.4)',
    },
  }[variant];

  return (
    <button
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        borderRadius: '8px',
        fontWeight: 500,
        fontFamily: 'var(--font-sans)',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.6 : 1,
        transition: 'all 0.15s ease-in-out',
        ...sizeStyles,
        ...variantStyles,
        ...style,
      }}
      disabled={disabled}
      {...props}
    >
      {icon}
      {children}
    </button>
  );
};
