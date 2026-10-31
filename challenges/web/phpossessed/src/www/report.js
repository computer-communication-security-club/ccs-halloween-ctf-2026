const picture = document.getElementById('picture');
const preview = document.getElementById('picture-preview');
let previewUrl;
picture.addEventListener('change', () => {
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  preview.hidden = true;
  picture.setCustomValidity('');
  const file = picture.files[0];
  if (!file) return;
  if (file.size > 1024 * 1024) {
    picture.setCustomValidity('Choose a picture no larger than 1 MB.');
    picture.reportValidity();
    return;
  }
  previewUrl = URL.createObjectURL(file);
  preview.src = previewUrl;
  preview.hidden = false;
});
