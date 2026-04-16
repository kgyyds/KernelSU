package me.weishu.kernelsu.ui

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.ui.NavDisplay
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.ui.navigation3.LocalNavigator
import me.weishu.kernelsu.ui.navigation3.Navigator
import me.weishu.kernelsu.ui.navigation3.Route
import me.weishu.kernelsu.ui.navigation3.rememberNavigator
import me.weishu.kernelsu.ui.screen.flash.FlashScreen
import me.weishu.kernelsu.ui.screen.install.InstallScreen
import me.weishu.kernelsu.ui.theme.KernelSUTheme
import me.weishu.kernelsu.ui.theme.LocalColorMode
import me.weishu.kernelsu.ui.theme.LocalEnableBlur
import me.weishu.kernelsu.ui.theme.LocalEnableFloatingBottomBar
import me.weishu.kernelsu.ui.theme.LocalEnableFloatingBottomBarBlur
import me.weishu.kernelsu.ui.util.install
import top.yukonga.miuix.kmp.basic.Scaffold

class MainActivity : ComponentActivity() {

    @SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val isManager = Natives.isManager
        if (isManager && !Natives.requireNewKernel()) install()

        setContent {
            val uiMode = UiMode.Miuix
            val darkMode = isSystemInDarkTheme()

            DisposableEffect(darkMode) {
                enableEdgeToEdge(
                    statusBarStyle = SystemBarStyle.auto(
                        android.graphics.Color.TRANSPARENT,
                        android.graphics.Color.TRANSPARENT
                    ) { darkMode },
                    navigationBarStyle = SystemBarStyle.auto(
                        android.graphics.Color.TRANSPARENT,
                        android.graphics.Color.TRANSPARENT
                    ) { darkMode },
                )
                window.isNavigationBarContrastEnforced = false
                onDispose { }
            }

            val navigator = rememberNavigator(Route.Install)
            val systemDensity = LocalDensity.current
            val density = remember(systemDensity) {
                Density(systemDensity.density, systemDensity.fontScale)
            }

            CompositionLocalProvider(
                LocalNavigator provides navigator,
                LocalDensity provides density,
                LocalColorMode provides if (darkMode) 2 else 1,
                LocalEnableBlur provides false,
                LocalEnableFloatingBottomBar provides false,
                LocalEnableFloatingBottomBarBlur provides false,
                LocalUiMode provides uiMode,
            ) {
                KernelSUTheme(appSettings = null, uiMode = uiMode) {
                    val navDisplay = @Composable {
                        NavDisplay(
                            backStack = navigator.backStack,
                            onBack = { navigator.pop() },
                            entryProvider = entryProvider {
                                entry<Route.Install> { InstallScreen() }
                                entry<Route.Flash> { key -> FlashScreen(key.flashIt) }
                            }
                        )
                    }

                    when (uiMode) {
                        UiMode.Material -> androidx.compose.material3.Scaffold { navDisplay() }
                        UiMode.Miuix -> Scaffold { navDisplay() }
                    }
                }
            }
        }
    }
}
