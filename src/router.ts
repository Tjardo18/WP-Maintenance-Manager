import { createRouter, createWebHashHistory } from "vue-router";
import DashboardView from "./views/DashboardView.vue";
import SitesView from "./views/SitesView.vue";
import SiteFormView from "./views/SiteFormView.vue";
import SiteDetailView from "./views/SiteDetailView.vue";
import HistoryView from "./views/HistoryView.vue";
import SettingsView from "./views/SettingsView.vue";
import ErrorLogView from "./views/ErrorLogView.vue";

export default createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", component: DashboardView, meta: { title: "Dashboard" } },
    { path: "/websites", component: SitesView, meta: { title: "Websites" } },
    { path: "/websites/toevoegen", component: SiteFormView, meta: { title: "Website toevoegen" } },
    { path: "/websites/:id/bewerken", component: SiteFormView, meta: { title: "Website bewerken" } },
    { path: "/websites/:id", component: SiteDetailView, meta: { title: "Websiteoverzicht" } },
    { path: "/historie", component: HistoryView, meta: { title: "Onderhoudshistorie" } },
    { path: "/foutenlog", component: ErrorLogView, meta: { title: "Foutenlog" } },
    { path: "/instellingen", component: SettingsView, meta: { title: "Instellingen" } },
  ],
});
