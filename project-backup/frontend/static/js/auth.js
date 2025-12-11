// Frontend auth controller for Hugo + Firebase Emulator
document.addEventListener("DOMContentLoaded", () => {
  firebase.auth().onAuthStateChanged(async (user) => {
    if (user) {
      toggleMenus(true);
    } else {
      toggleMenus(false);
    }
  });
});

// Global logout override
document.addEventListener('click', (e) => {
  if (e.target.id === 'logout-button') {
    e.preventDefault();
    firebase.auth().signOut().then(() => {
      toggleMenus(false);
      window.location.href = '/';
    });
  }
});

