package org.connecttag.lib.features.applock

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

/**
 * Descriptor for a launcher `<activity-alias>` camouflage preset (e.g., Calculator, Notes, Utility).
 */
public data class AppLauncherDisguiseOption(
    public val id: String,
    public val componentClassName: String,
    public val displayName: String,
    public val taskMask: AppRecentsTaskMask? = null,
) {
    init {
        require(id.isNotBlank()) { "Disguise option id must not be blank" }
        require(componentClassName.isNotBlank()) { "Disguise componentClassName must not be blank" }
    }
}

/**
 * Outcome of switching the active launcher component/alias.
 */
public sealed interface AppLauncherSwitchResult {
    public data class Applied(public val activeComponentClassName: String) : AppLauncherSwitchResult
    public data class TargetNotFound(public val targetComponentClassName: String) : AppLauncherSwitchResult
    public data class Failed(public val reason: String) : AppLauncherSwitchResult
}

/**
 * Fail-safe controller for switching between the primary launcher activity/alias and
 * stealth camouflage `<activity-alias>` entries.
 *
 * Guarantees that the target launcher component is enabled **before** any other alias is disabled,
 * preventing accidental loss of all launcher icons.
 */
public class AppLauncherAliasController(
    context: Context,
    public val defaultLauncherComponentClassName: String,
    public val disguiseOptions: List<AppLauncherDisguiseOption> = emptyList(),
) {
    private val appContext: Context = context.applicationContext
    private val packageManager: PackageManager = appContext.packageManager

    init {
        require(defaultLauncherComponentClassName.isNotBlank()) {
            "defaultLauncherComponentClassName must not be blank"
        }
    }

    /**
     * Switches the active launcher icon/label to the disguise option matching [disguiseId],
     * or restores [defaultLauncherComponentClassName] when [disguiseId] is `null`.
     */
    public fun applyDisguise(disguiseId: String?): AppLauncherSwitchResult {
        val targetOption = disguiseId?.let { id ->
            disguiseOptions.firstOrNull { option -> option.id == id }
        }
        val targetClassName = targetOption?.componentClassName ?: defaultLauncherComponentClassName
        return switchLauncherComponent(targetClassName)
    }

    /**
     * Restores the default application launcher icon and label.
     */
    public fun restoreDefaultLauncher(): AppLauncherSwitchResult =
        switchLauncherComponent(defaultLauncherComponentClassName)

    /**
     * Returns the currently enabled [AppLauncherDisguiseOption], or `null` if the default
     * launcher component is active.
     */
    public fun resolveActiveDisguise(): AppLauncherDisguiseOption? =
        disguiseOptions.firstOrNull { option ->
            val component = ComponentName(appContext.packageName, option.componentClassName)
            packageManager.getComponentEnabledSetting(component) ==
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        }

    private fun switchLauncherComponent(targetClassName: String): AppLauncherSwitchResult {
        return runCatching {
            val allClassNames = buildList {
                add(defaultLauncherComponentClassName)
                disguiseOptions.forEach { option -> add(option.componentClassName) }
            }.distinct()

            if (targetClassName !in allClassNames) {
                return AppLauncherSwitchResult.TargetNotFound(targetClassName)
            }

            val targetComponent = ComponentName(appContext.packageName, targetClassName)
            // Enable the target component FIRST so at least one launcher entry is always active.
            packageManager.setComponentEnabledSetting(
                targetComponent,
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                PackageManager.DONT_KILL_APP,
            )

            allClassNames
                .filter { className -> className != targetClassName }
                .forEach { className ->
                    val component = ComponentName(appContext.packageName, className)
                    packageManager.setComponentEnabledSetting(
                        component,
                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        PackageManager.DONT_KILL_APP,
                    )
                }

            AppLauncherSwitchResult.Applied(targetClassName)
        }.getOrElse { error ->
            AppLauncherSwitchResult.Failed(error.message ?: "Launcher alias switch failed")
        }
    }
}
