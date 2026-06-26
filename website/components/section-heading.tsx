interface SectionHeadingProps {
  eyebrow?: string
  title: string
  description?: string
  align?: 'left' | 'center'
}

export function SectionHeading({
  eyebrow,
  title,
  description,
  align = 'center',
}: SectionHeadingProps) {
  return (
    <div className={align === 'center' ? 'mx-auto max-w-2xl text-center' : 'max-w-2xl'}>
      {eyebrow && (
        <span className="inline-flex items-center gap-3 text-xs uppercase tracking-[0.35em] text-gold">
          <span className="h-px w-8 bg-gold" />
          {eyebrow}
        </span>
      )}
      <h2 className="mt-5 text-balance font-serif text-3xl leading-tight text-cream sm:text-4xl lg:text-5xl">
        {title}
      </h2>
      {description && (
        <p className="mt-5 text-pretty leading-relaxed text-muted-foreground">{description}</p>
      )}
    </div>
  )
}
