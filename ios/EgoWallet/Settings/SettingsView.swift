import EgoKit
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var app: AppModel
    @State private var phrase: [String]?
    @State private var problem: String?
    @State private var confirmRemove = false
    @State private var knownGateways = 0
    @State private var copied = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Wallet") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Address").font(.caption).foregroundStyle(Brand.muted)
                        Text(app.address)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    Button(copied ? "Copied" : "Copy address") {
                        UIPasteboard.general.string = app.address
                        copied = true
                    }
                    if let phrase {
                        PhraseGrid(words: phrase)
                            .listRowInsets(EdgeInsets(top: 8, leading: 8, bottom: 8, trailing: 8))
                        Button("Hide recovery phrase") { self.phrase = nil }
                    } else {
                        Button("Show recovery phrase") { Task { await reveal() } }
                    }
                    if let problem {
                        Text(problem).foregroundStyle(Brand.danger)
                    }
                }
                Section {
                    LabeledContent("Internet", value: app.online ? "Connected" : "Offline")
                    LabeledContent("Connected through", value: app.gatewayHost ?? "Not connected yet")
                    LabeledContent("Gateways this phone knows", value: "\(knownGateways)")
                } header: {
                    Text("Network")
                } footer: {
                    Text("Phones reach the Ego network through Ego Desktop computers that offer to act as gateways. Gateways only pass messages along. Your keys and signatures stay on this iPhone.")
                }
                Section {
                    Button("Lock wallet") { app.lock() }
                }
                Section {
                    Button("Remove wallet from this iPhone", role: .destructive) { confirmRemove = true }
                } footer: {
                    Text("Your coins stay on the network. You'll need your 24 words to get the wallet back.")
                }
            }
            .scrollContentBackground(.hidden)
            .screenBackground()
            .navigationTitle("Settings")
            .confirmationDialog("Remove this wallet from the iPhone?", isPresented: $confirmRemove, titleVisibility: .visible) {
                Button("Remove wallet", role: .destructive) { app.deleteWallet() }
            } message: {
                Text("Only do this if your 24 words are written down. Without them the wallet is gone for good.")
            }
            .task { knownGateways = await app.directory.known.count }
            .onDisappear {
                phrase = nil
                copied = false
            }
        }
    }

    private func reveal() async {
        do {
            phrase = try await app.revealPhrase()
            problem = nil
        } catch VaultError.cancelled {
            problem = nil
        } catch {
            problem = app.message(for: error)
        }
    }
}
