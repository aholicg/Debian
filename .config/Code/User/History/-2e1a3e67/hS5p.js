const { Tray, Menu, nativeImage } = require('electron')
const path = require('node:path')
const https = require('https')

function setupBackgroundController({ app, createWindow, isBackgroundOnly }) {
  const noop = () => {}
  const singleInstance = app.requestSingleInstanceLock()

  if (!singleInstance) {
    app.quit()
    return {
      showWindow: noop,
      hideWindow: noop,
      toggleWindow: noop
    }
  }

  let tray = null
  let mainWindow = null
  let isQuitting = false

  const iconUrl = 'https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fibrand.vn%2Fwp-content%2Fuploads%2F2024%2F09%2Flogo-bach-khoa-2-768x1152.jpg&f=1&nofb=1&ipt=9ee07fc7c498234ec2f6ef4012b6d4ffa36dc23d41159f0953d42765e24bf88f'
  const iconPath = path.join(__dirname, 'assets', 'icon.png')
  let trayIcon = iconPath

  // Try to load icon from URL first, fallback to local file
  try {
    https.get(iconUrl, (response) => {
      const chunks = []
      response.on('data', (chunk) => chunks.push(chunk))
      response.on('end', () => {
        const buffer = Buffer.concat(chunks)
        const iconImage = nativeImage.createFromBuffer(buffer)
        if (!iconImage.isEmpty()) {
          trayIcon = iconImage
          if (tray) {
            tray.setImage(iconImage)
          }
        }
      })
    }).on('error', (err) => {
      console.warn('[Background] Failed to load tray icon from URL, trying local file.', err.message)
    })
  } catch (err) {
    console.warn('[Background] Failed to fetch tray icon from URL.', err.message)
  }

  // Fallback to local icon
  try {
    const iconImage = nativeImage.createFromPath(iconPath)
    if (!iconImage.isEmpty()) {
      trayIcon = iconImage
    }
  } catch (err) {
    console.warn('[Background] Failed to load tray icon, falling back to path.', err.message)
  }

  const ensureTray = () => {
    if (tray) {
      return tray
    }

    tray = new Tray(trayIcon)
    tray.setToolTip('mAIware')

    tray.on('click', toggleWindow)
    tray.on('double-click', showWindow)
    tray.on('right-click', () => {
      updateContextMenu()
    })

    updateContextMenu()
    return tray
  }

  const destroyTray = () => {
    if (tray) {
      tray.destroy()
      tray = null
    }
  }

  const windowIsUsable = () => mainWindow && !mainWindow.isDestroyed()

  const hideDockIfNeeded = () => {
    if (process.platform === 'darwin' && app.dock && typeof app.dock.hide === 'function') {
      app.dock.hide()
    }
  }

  const showDockIfNeeded = () => {
    if (process.platform === 'darwin' && app.dock && typeof app.dock.show === 'function') {
      app.dock.show()
    }
  }

  const updateContextMenu = () => {
    if (!tray) {
      return
    }

    const hasWindow = windowIsUsable()
    const isVisible = hasWindow && mainWindow.isVisible()

    const template = [
      {
        label: isVisible ? 'Hide Window' : 'Show Window',
        enabled: hasWindow || typeof createWindow === 'function',
        click: toggleWindow
      },
      { type: 'separator' },
      {
        label: 'Quit',
        click: quitApplication
      }
    ]

    tray.setContextMenu(Menu.buildFromTemplate(template))
  }

  const showWindow = () => {
    if (windowIsUsable()) {
      showDockIfNeeded()
      if (!mainWindow.isVisible()) {
        mainWindow.show()
      }
      mainWindow.focus()
      updateContextMenu()
      return mainWindow
    }

    if (typeof createWindow !== 'function') {
      return null
    }

    let newWindow
    try {
      newWindow = createWindow()
    } catch (err) {
      console.error('[Background] Failed to create window:', err)
      return null
    }

    if (isBackgroundOnly && newWindow && typeof newWindow.once === 'function') {
      newWindow.once('ready-to-show', () => {
        newWindow.show()
        newWindow.focus()
        updateContextMenu()
      })
    }

    return newWindow || null
  }

  const hideWindow = () => {
    if (!windowIsUsable()) {
      updateContextMenu()
      return
    }

    mainWindow.hide()
    hideDockIfNeeded()
    updateContextMenu()
  }

  const toggleWindow = () => {
    if (!windowIsUsable()) {
      showWindow()
      return
    }

    if (mainWindow.isVisible()) {
      hideWindow()
    } else {
      showWindow()
    }
  }

  const quitApplication = () => {
    isQuitting = true
    showDockIfNeeded()
    destroyTray()
    if (windowIsUsable()) {
      mainWindow.close()
    }
    app.quit()
  }

  const handleWindowCreated = (window) => {
    mainWindow = window

    ensureTray()
    updateContextMenu()

    window.on('close', (event) => {
      if (isQuitting) {
        return
      }

      event.preventDefault()
      hideWindow()
    })

    window.on('minimize', (event) => {
      if (isQuitting) {
        return
      }

      event.preventDefault()
      hideWindow()
    })

    window.on('show', () => {
      showDockIfNeeded()
      updateContextMenu()
    })

    window.on('hide', () => {
      hideDockIfNeeded()
      updateContextMenu()
    })

    window.on('closed', () => {
      mainWindow = null
      updateContextMenu()

      if (!isQuitting) {
        hideDockIfNeeded()
      }
    })
  }

  app.on('browser-window-created', (_event, window) => {
    handleWindowCreated(window)
  })

  app.on('before-quit', () => {
    isQuitting = true
    destroyTray()
  })

  app.on('second-instance', () => {
    showWindow()
  })

  app.whenReady().then(() => {
    if (isBackgroundOnly) {
      ensureTray()
      updateContextMenu()
      hideDockIfNeeded()
    }
  })

  return {
    showWindow,
    hideWindow,
    toggleWindow
  }
}

module.exports = { setupBackgroundController }
