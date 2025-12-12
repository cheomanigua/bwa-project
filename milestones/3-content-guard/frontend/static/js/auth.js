export async function updateNavVisibility() {
  try {
    const res = await fetch("/api/session", { credentials: "include" });
    const data = await res.json();

    const visitorMenus = document.querySelectorAll(".visitor-menu");
    const memberMenus = document.querySelectorAll(".member-menu");

    if (data.loggedIn) {
      visitorMenus.forEach((el) => (el.style.display = "none"));
      memberMenus.forEach((el) => (el.style.display = "list-item"));
    } else {
      memberMenus.forEach((el) => (el.style.display = "none"));
      visitorMenus.forEach((el) => (el.style.display = "list-item"));
    }
  } catch (err) {
    console.error("Menu update failed:", err);
  }
}
