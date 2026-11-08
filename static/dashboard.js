/* Arbeitszeit 30: nur lokale Darstellung, kein Hintergrund-Polling. */
(() => {
  "use strict";

  const live = document.getElementById("live-work-time");
  if (live) {
    const initial = Number(live.dataset.seconds);
    const running = live.dataset.running === "1";
    const started = Date.now();
    let interval = null;

    function hhmmss(totalSeconds) {
      const n = Math.max(0, Math.floor(totalSeconds));
      const hours = Math.floor(n / 3600);
      const minutes = String(Math.floor((n % 3600) / 60)).padStart(2, "0");
      const seconds = String(n % 60).padStart(2, "0");
      return hours + ":" + minutes + ":" + seconds + " h";
    }

    function update() {
      const elapsed = running ? Math.max(0, Math.floor((Date.now() - started) / 1000)) : 0;
      live.textContent = hhmmss(initial + elapsed);
    }

    function syncVisibility() {
      if (interval !== null) {
        clearInterval(interval);
        interval = null;
      }
      update();
      if (!document.hidden && running) {
        interval = setInterval(update, 1000);
      }
    }

    document.addEventListener("visibilitychange", syncVisibility);
    window.addEventListener("pageshow", syncVisibility);
    syncVisibility();
  }

  // Teamansicht: nur während sichtbarer Seite neu vom Server laden.
  const teamRefresh = document.getElementById("team-auto-refresh");
  if (teamRefresh) {
    const configured = Number(teamRefresh.dataset.interval);
    const period = Number.isFinite(configured)
      ? Math.max(15000, configured) : 30000;
    let interval = null;
    function syncTeamRefresh() {
      if (interval !== null) clearInterval(interval);
      interval = null;
      if (!document.hidden) {
        interval = setInterval(() => {
          if (!document.hidden && navigator.onLine !== false) {
            window.location.reload();
          }
        }, period);
      }
    }
    document.addEventListener("visibilitychange", syncTeamRefresh);
    window.addEventListener("pageshow", syncTeamRefresh);
    syncTeamRefresh();
  }

  for (const form of document.querySelectorAll('form[action="/punch"]')) {
    form.addEventListener("submit", () => {
      for (const button of form.querySelectorAll('button[type="submit"],button:not([type])')) {
        button.disabled = true;
        button.textContent = "Buchung wird gespeichert …";
      }
    });
  }

  const banner = document.getElementById("connection-status");
  if (banner) {
    const updateConnection = () => {
      const offline = navigator.onLine === false;
      banner.hidden = !offline;
      banner.textContent = offline
        ? "Gerät meldet keine Netzwerkverbindung. Buchungen nur bei erreichbarem Server möglich."
        : "";
    };
    window.addEventListener("offline", updateConnection);
    window.addEventListener("online", updateConnection);
    updateConnection();
  }
})();
