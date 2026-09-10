"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { Container } from "./container";

const links = [
  { href: "/#hizmetler", label: "Hizmetler" },
  { href: "/#surec", label: "Süreç" },
  { href: "/#metodoloji", label: "Metodoloji" },
  { href: "/#sss", label: "SSS" },
];

export function Header({ name }: { name: string }) {
  const [open, setOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const headerRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
        toggleRef.current?.focus();
      }
    }
    function onOutside(event: PointerEvent) {
      if (event.target instanceof Node && !headerRef.current?.contains(event.target)) setOpen(false);
    }
    const desktop = window.matchMedia("(min-width: 1024px)");
    const onDesktop = () => { if (desktop.matches) setOpen(false); };
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onOutside);
    desktop.addEventListener("change", onDesktop);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onOutside);
      desktop.removeEventListener("change", onDesktop);
    };
  }, [open]);

  return (
    <header className="site-header" ref={headerRef} onBlur={(event) => {
      if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
    }}>
      <Container className="header-inner">
        <Link className="brand" href="/" onClick={() => setOpen(false)} aria-label={`${name} — Ana sayfa`}>{name}</Link>
        <button ref={toggleRef} className="menu-toggle" type="button" aria-expanded={open} aria-controls="main-navigation" onClick={() => setOpen(!open)}>
          {open ? "Menüyü kapat" : "Menü"}<span aria-hidden="true">{open ? "−" : "+"}</span>
        </button>
        <nav id="main-navigation" className={`main-navigation ${open ? "is-open" : ""}`} aria-label="Ana gezinme">
          {links.map((link) => <Link key={link.href} href={link.href} onClick={() => setOpen(false)}>{link.label}</Link>)}
          <Link className="button button-primary nav-cta" href="/test-talep-et" onClick={() => setOpen(false)}>Test Talep Et</Link>
        </nav>
      </Container>
    </header>
  );
}
