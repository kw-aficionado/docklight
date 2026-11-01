# Anti-cheat guidance

Templates can include an informational **Anti-cheat** tab with Anti-Xray, BattlEye, and plugin-recommendation cards. The tab is visible to users with `server.files` on servers whose template includes `anticheat` metadata. It does not inspect installed plugins, detect cheating, edit configuration, or install anything.

The built-in Minecraft Java template declares Paper Anti-Xray as available when the server type is **PAPER**. Paper stores its world defaults in `config/paper-world-defaults.yml`; Anti-Xray is disabled by default and needs a server restart after configuration changes. See the official [Paper Anti-Xray guide](https://docs.papermc.io/paper/anti-xray/) and [world-configuration reference](https://docs.papermc.io/paper/reference/world-configuration/).

Custom templates can add hints using this shape:

```yaml
gameskill:
  anticheat:
    antixray:
      supported: true
      config_hint: "Available with the Paper server type; configure it in paper-world-defaults.yml."
    battleye:
      supported: false
      config_hint: "This template does not include BattlEye."
    plugins_recommended:
      - "Example server plugin"
```

Hints are plain text, bounded to 2,000 characters per feature. A template can list up to 16 plugin names. Docklight treats this as reference information supplied by the template author; review the upstream project's own documentation before relying on a recommendation.
