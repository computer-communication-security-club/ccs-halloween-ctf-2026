// Default to Halloween midnight; preserve rCTF's native light/dark preference.
;(() => {
  let theme = 'dark'
  try {
    const saved = localStorage.getItem('theme')
    if (saved === 'light' || saved === 'dark') theme = saved
  } catch {}
  document.documentElement.dataset.theme = theme
})()
