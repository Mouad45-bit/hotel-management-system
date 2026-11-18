interface PageBannerProps {
  eyebrow?: string
  title: string
  description?: string
}

export function PageBanner({ eyebrow, title, description }: PageBannerProps) {
  return (
    <section className="relative overflow-hidden border-b border-border bg-card pt-36 pb-16 lg:pt-44 lg:pb-20">
      <div className="mx-auto max-w-7xl px-6 text-center lg:px-10">
        {eyebrow && (
          <span className="inline-flex items-center gap-3 text-xs uppercase tracking-[0.35em] text-gold">
            <span className="h-px w-8 bg-gold" />
            {eyebrow}
            <span className="h-px w-8 bg-gold" />
          </span>
        )}
        <h1 className="mt-5 text-balance font-serif text-4xl text-cream sm:text-5xl lg:text-6xl">
          {title}
        </h1>
        {description && (
          <p className="mx-auto mt-5 max-w-2xl text-pretty leading-relaxed text-muted-foreground">
            {description}
          </p>
        )}
      </div>
    </section>
  )
}
