import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap cursor-pointer transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 disabled:pointer-events-none disabled:opacity-50 disabled:cursor-not-allowed active:scale-[0.97] [&_svg]:pointer-events-none [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "gap-2 bg-primary text-primary-foreground shadow-md hover:bg-primary/90 hover:shadow-lg",
        destructive: "gap-2 bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90 hover:shadow-md",
        outline:
          "gap-2 border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground hover:shadow-md",
        secondary: "gap-2 bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80",
        ghost: "gap-2 hover:bg-accent hover:text-accent-foreground",
        link: "gap-2 text-primary underline-offset-4 hover:underline",
        accent: "gap-1.5 rounded border border-primary/40 bg-primary/10 text-primary hover:bg-primary/20",
        neutral: "gap-1.5 rounded border border-border bg-surface-2 text-muted-foreground hover:border-primary/40 hover:text-foreground",
        danger: "gap-1.5 rounded-md border border-destructive/40 bg-destructive/10 text-destructive hover:bg-destructive/20",
      },
      size: {
        default: "h-9 px-4 py-2 text-sm font-medium rounded-md [&_svg]:size-4",
        sm: "h-8 rounded-md px-3 text-xs [&_svg]:size-4",
        lg: "h-10 rounded-md px-8 [&_svg]:size-4",
        icon: "h-9 w-9 rounded-md [&_svg]:size-4",
        xs: "gap-1 rounded px-2 py-1.5 text-mono ba-text-2xs [&_svg]:size-3",
        "xs-icon": "gap-2.5 rounded px-2.5 py-1.5 text-mono ba-text-2xs [&_svg]:size-3",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };
