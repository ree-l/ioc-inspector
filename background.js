// On install: open onboarding page first time
chrome.runtime.onInstalled.addListener(async (details) => {
  chrome.contextMenus.create({
    id: "ioc-inspect-selection",
    title: "Inspect with IOC Inspector",
    contexts: ["selection", "link"],
  });

  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("onboarding.html") });
  }
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== "ioc-inspect-selection") return;
  const target = info.linkUrl || info.selectionText;
  if (!target) return;
  await chrome.storage.local.set({ pending_lookup: target.trim() });
  chrome.action.openPopup();
});
