package org.connecttag.lib.features.applock

import android.app.Activity
import android.app.ActivityManager
import android.os.Build
import android.view.WindowManager
import androidx.annotation.DrawableRes
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap

/**
 * Optional task description metadata for disguising the application in Android's Recents overview.
 */
public data class AppRecentsTaskMask(
    public val label: String,
    @param:DrawableRes public val iconResId: Int? = null,
)

/**
 * Single owner for `WindowManager.LayoutParams.FLAG_SECURE` and Recent-Apps task masking.
 *
 * Extracted from `com.protection.connected` (`StealthWindowPrivacy`) so that leaving a nested
 * sensitive screen never inadvertently clears global recents snapshot protection while app lock is active.
 */
public class AppLockWindowPrivacyController {
    private var globalSecureRecents: Boolean = false
    private var activeSensitiveScreenCount: Int = 0

    /**
     * Updates global recents snapshot protection and optionally masks the task title/icon in Recents.
     */
    public fun update(
        activity: Activity,
        secureSnapshot: Boolean,
        taskMask: AppRecentsTaskMask? = null,
    ) {
        globalSecureRecents = secureSnapshot
        applySecureFlag(activity)

        if (taskMask != null) {
            applyTaskMask(activity, taskMask)
        }
    }

    /**
     * Acquires or releases a reference-counted sensitive screen lock on [activity].
     */
    public fun setSensitiveScreen(activity: Activity, secure: Boolean) {
        val delta = if (secure) 1 else -1
        activeSensitiveScreenCount = (activeSensitiveScreenCount + delta).coerceAtLeast(0)
        applySecureFlag(activity)
    }

    private fun applySecureFlag(activity: Activity) {
        if (globalSecureRecents || activeSensitiveScreenCount > 0) {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    private fun applyTaskMask(activity: Activity, mask: AppRecentsTaskMask) {
        runCatching {
            val description = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val builder = ActivityManager.TaskDescription.Builder().setLabel(mask.label)
                if (mask.iconResId != null) {
                    builder.setIcon(mask.iconResId)
                }
                builder.build()
            } else {
                val bitmap = mask.iconResId?.let { resId ->
                    ContextCompat.getDrawable(activity, resId)?.toBitmap(
                        TASK_ICON_SIZE_PX,
                        TASK_ICON_SIZE_PX,
                    )
                }
                @Suppress("DEPRECATION")
                ActivityManager.TaskDescription(mask.label, bitmap)
            }
            activity.setTaskDescription(description)
        }
    }

    public companion object {
        private const val TASK_ICON_SIZE_PX: Int = 96
    }
}
