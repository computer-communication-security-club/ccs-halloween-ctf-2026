import { useEffect, useRef, useState } from "react";
import { createOrder, getShells } from "./api.js";

const money = (cents, currency = "USD") => new Intl.NumberFormat("en-US", { style: "currency", currency }).format(cents / 100);
const prompts = { bash: "$", zsh: "%", fish: ">" };

export default function App() {
  const [shells, setShells] = useState([]);
  const [cart, setCart] = useState({});
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [checkoutError, setCheckoutError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [order, setOrder] = useState(null);
  const checkoutLock = useRef(false);

  async function loadCatalog() {
    setLoading(true);
    setLoadError("");
    try { setShells(await getShells()); }
    catch (error) { setLoadError(error.message); }
    finally { setLoading(false); }
  }

  useEffect(() => { loadCatalog(); }, []);

  const lines = shells.filter((shell) => cart[shell.id]).map((shell) => ({ ...shell, quantity: cart[shell.id] }));
  const count = lines.reduce((sum, line) => sum + line.quantity, 0);
  const total = lines.reduce((sum, line) => sum + line.priceCents * line.quantity, 0);
  const invalidStock = lines.some((line) => line.quantity > Math.min(line.stock, 100));

  function changeQuantity(shell, delta) {
    setCart((current) => {
      const quantity = Math.max(0, Math.min(Math.min(shell.stock, 100), (current[shell.id] || 0) + delta));
      return { ...current, [shell.id]: quantity };
    });
    setCheckoutError("");
    setOrder(null);
  }

  async function checkout(event) {
    event.preventDefault();
    if (checkoutLock.current || !lines.length || invalidStock) return;
    checkoutLock.current = true;
    setSubmitting(true);
    setCheckoutError("");
    try {
      const result = await createOrder(lines.map(({ id, quantity }) => ({ shellId: id, quantity })));
      setOrder(result);
      setCart({});
      setShells((current) => current.map((shell) => ({
        ...shell,
        stock: shell.stock - (result.items.find((item) => item.shellId === shell.id)?.quantity || 0),
      })));
    } catch (error) {
      setCheckoutError(error.message);
    } finally {
      checkoutLock.current = false;
      setSubmitting(false);
    }
  }

  return (
    <>
    <div className="sale-banner" role="marquee" aria-label="Shelloween sale">
      <div className="sale-track">
        {Array.from({ length: 2 }).map((_, i) => (
          <span key={i}>🎃 SPECIAL SHELLOWEEN SALE &nbsp;•&nbsp; 31% OFF EVERY SHELL &nbsp;•&nbsp; SPOOKY PRICES ALL HALLOW'S EVE &nbsp;•&nbsp; BUY ONE, GET ONE HAUNTED &nbsp;•&nbsp; FREE GHOST WITH EVERY ORDER &nbsp;•&nbsp; 👻&nbsp;&nbsp;&nbsp;</span>
        ))}
      </div>
    </div>
    <div className="layout">
      <header className="header">
        <a href="#" className="brand" aria-label="Shelloween Market home"><span className="brand-icon">&gt;_</span> shelloween<span className="brand-dot">.</span></a>
        <a className="cart-link" href="#cart">Your cauldron <span>{count}</span></a>
      </header>
      <main>
        <section className="hero" aria-labelledby="title">
          <div><p className="eyebrow">🎃 SOMETHING WICKED THIS WAY COMPILES</p><h1 id="title">Summon your<br />next <em>shell.</em></h1><p className="intro">Classic, cursed, or a little more friendly.<br />Every shell a growing goblin could want — this season only.</p><a className="browse-link" href="#catalog">Enter the crypt <span aria-hidden="true">↘</span></a></div>
          <div className="terminal" aria-label="Decorative terminal example"><div className="terminal-bar"><span>● ● ●</span><span>shelloween — ~</span></div><div className="terminal-body"><p><span className="muted">visitor@graveyard</span> ~</p><p><span className="green">$</span> conjure --shell my-next-shell</p><p className="terminal-output">Rattling the bones, stirring the pot…</p><p className="green">✓ A prompt full of wicked possibilities.</p><p><span className="green">$</span> <span className="cursor" /></p></div></div>
        </section>
        <div className="market-grid">
          <section id="catalog" aria-labelledby="catalog-title">
            <div className="section-heading"><h2 id="catalog-title">The haunted collection</h2><span>01 — {String(shells.length).padStart(2, "0")}</span></div>
            {loading && <p role="status" className="notice">Summoning the collection…</p>}
            {loadError && <div className="notice" role="alert"><p>{loadError}</p><button onClick={loadCatalog}>Try again</button></div>}
            {!loading && !loadError && !shells.length && <p className="notice">The collection is empty. Check back soon.</p>}
            <div className="products">{shells.map((shell, index) => (
              <article className="product" key={shell.id}>
                <div className={`product-art art-${index % 3}`} aria-hidden="true"><span>{prompts[shell.id] || "$"}<span className="underscore">_</span></span><small>/{shell.id}</small></div>
                <div className="product-info"><div className="product-title"><h3>{shell.name}</h3><span>{money(shell.priceCents, shell.currency)}</span></div><p>{shell.description}</p><div className="product-footer"><span className="stock">{shell.stock > 0 ? `${shell.stock} available` : "Sold out"}</span><button className="add-button" disabled={submitting || shell.stock <= (cart[shell.id] || 0) || (cart[shell.id] || 0) >= 100} onClick={() => changeQuantity(shell, 1)} aria-label={`Add ${shell.name} to cart`}>Add <span aria-hidden="true">+</span></button></div></div>
              </article>
            ))}</div>
          </section>
          <aside id="cart" className="cart" aria-labelledby="cart-title">
            <div className="section-heading"><h2 id="cart-title">Your cauldron</h2><span>{count} items</span></div>
            {order && <div className="confirmation" role="status"><h3>Order received.</h3><p>{money(order.totalCents, order.currency)} · {order.status}</p><p className="order-id">Reference: {order.id}</p><p>Payment and delivery are not connected yet.</p></div>}
            {!lines.length && !order && <div className="empty-cart"><span aria-hidden="true">🦇</span><h3>The cauldron is empty.</h3><p>Your next cursed shell<br />lurks in the collection.</p></div>}
            <form onSubmit={checkout}>
              {lines.map((line) => <div className="cart-line" key={line.id}><div><strong>{line.name}</strong><p>{money(line.priceCents * line.quantity, line.currency)}</p></div><div className="quantity"><button type="button" disabled={submitting} onClick={() => changeQuantity(line, -1)} aria-label={`Remove one ${line.name}`}>−</button><span>{line.quantity}</span><button type="button" disabled={submitting || line.quantity >= Math.min(line.stock, 100)} onClick={() => changeQuantity(line, 1)} aria-label={`Add one ${line.name}`}>+</button></div></div>)}
              <div className="total"><span>Total</span><strong>{money(total)}</strong></div>
              {checkoutError && <p role="alert" className="error">{checkoutError} <button type="button" onClick={loadCatalog}>Refresh stock</button></p>}
              {invalidStock && <p role="alert" className="error">Stock changed. Reduce or remove unavailable items.</p>}
              <button className="checkout" disabled={!lines.length || submitting || invalidStock || loading || Boolean(loadError)}>{submitting ? "Placing order…" : "Place order"}<span aria-hidden="true">↗</span></button>
              <p className="cart-note">Demo checkout · No souls required</p>
            </form>
          </aside>
        </div>
      </main>
      <footer><span>shelloween. <span className="muted">A wicked place to begin.</span></span><span>Brewed for life at the command line. 🕯️</span></footer>
    </div>
    </>
  );
}
