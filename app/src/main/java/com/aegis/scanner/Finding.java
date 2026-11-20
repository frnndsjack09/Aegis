package com.aegis.scanner;

import java.util.ArrayList;
import java.util.List;

/** One result line in the report: what we found, how bad it is, and what to do. */
public class Finding {

    /** RED = act now, YELLOW = review, INFO = good to know, GREEN = all fine. */
    public enum Level { RED, YELLOW, INFO, GREEN }

    /** What a button under the finding does. */
    public enum ActionType { APP_INFO, UNINSTALL, OPEN_SETTINGS, OPEN_URL, DIAL, TRUST_APP, COPY }

    public static class Action {
        public final String label;
        public final ActionType type;
        /** Package name, Settings action string, URL or phone code, depending on type. */
        public final String target;

        public Action(String label, ActionType type, String target) {
            this.label = label;
            this.type = type;
            this.target = target;
        }
    }

    public final Level level;
    public final String category;
    public final String title;
    /** Not final: the scan appends "last used" times once all findings exist. */
    public String detail;
    public final List<Action> actions = new ArrayList<>();

    public Finding(Level level, String category, String title, String detail) {
        this.level = level;
        this.category = category;
        this.title = title;
        this.detail = detail;
    }

    public Finding action(String label, ActionType type, String target) {
        actions.add(new Action(label, type, target));
        return this;
    }

    /** Standard buttons for an app: App info, Uninstall, and "I trust this". */
    public Finding appActions(String pkg) {
        action("App info", ActionType.APP_INFO, pkg);
        action("Uninstall", ActionType.UNINSTALL, pkg);
        action("I trust this app", ActionType.TRUST_APP, pkg);
        return this;
    }
}
