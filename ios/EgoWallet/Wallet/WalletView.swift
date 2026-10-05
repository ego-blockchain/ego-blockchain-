import CoreImage.CIFilterBuiltins
import EgoKit
import SwiftUI

struct WalletView: View {
    @EnvironmentObject private var model: AppModel
    @State private var sending = false
    @State private var receiving = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    balanceCard
                    if let problem = model.problem {
                        ProblemBanner(text: problem)
                    }
                    SectionLabel(text: "Activity")
                    if model.history.isEmpty {
                        Text(model.refreshing ? "Loading…" : "No transactions yet.")
                            .foregroundStyle(Brand.muted)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .card()
                    } else {
                        VStack(spacing: 0) {
                            ForEach(model.history) { item in
                                ActivityRow(item: item, me: model.address)
                                if item.id != model.history.last?.id {
                                    Divider().overlay(Brand.line)
                                }
                            }
                        }
                        .card()
                    }
                }
                .padding(16)
            }
            .refreshable { await model.refresh() }
            .screenBackground()
            .navigationTitle("Wallet")
            .sheet(isPresented: $sending) { SendView() }
            .sheet(isPresented: $receiving) { ReceiveView(address: model.address) }
            .task { await model.refresh() }
        }
    }

    private var balanceCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionLabel(text: "Balance")
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(model.balance.map { Amount.format($0, maxDecimals: 2) } ?? "…")
                    .font(.system(size: 40, weight: .heavy, design: .rounded))
                    .foregroundStyle(Brand.text)
                    .contentTransition(.numericText())
                Text("EGOC")
                    .font(.system(.headline, design: .rounded))
                    .foregroundStyle(Brand.lime)
            }
            Text(shortAddress(model.address))
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(Brand.muted)
            HStack(spacing: 12) {
                Button {
                    sending = true
                } label: {
                    Label("Send", systemImage: "arrow.up.right")
                }
                .buttonStyle(PrimaryButtonStyle())
                Button {
                    receiving = true
                } label: {
                    Label("Receive", systemImage: "arrow.down.left")
                }
                .buttonStyle(SecondaryButtonStyle())
            }
        }
        .card()
    }
}

struct ActivityRow: View {
    let item: HistoryItem
    let me: String

    var body: some View {
        let incoming = item.to == me && item.from != me
        HStack(spacing: 12) {
            Image(systemName: incoming ? "arrow.down.left" : "arrow.up.right")
                .font(.system(size: 14, weight: .bold))
                .frame(width: 34, height: 34)
                .background((incoming ? Brand.mint : Brand.lime).opacity(0.15))
                .foregroundStyle(incoming ? Brand.mint : Brand.lime)
                .clipShape(Circle())
            VStack(alignment: .leading, spacing: 3) {
                Text(incoming ? "Received" : "Sent")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Brand.text)
                Text(incoming ? "From \(shortAddress(item.from))" : "To \(shortAddress(item.to))")
                    .font(.caption)
                    .foregroundStyle(Brand.muted)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 3) {
                Text("\(incoming ? "+" : "−")\(Amount.format(item.amount, maxDecimals: 4))")
                    .font(.system(.subheadline, design: .rounded, weight: .semibold))
                    .foregroundStyle(incoming ? Brand.mint : Brand.text)
                Text(item.blockHeight == nil ? "Pending" : relativeTime(item.timestamp))
                    .font(.caption)
                    .foregroundStyle(item.blockHeight == nil ? Brand.warning : Brand.muted)
            }
        }
        .padding(.vertical, 10)
    }
}

struct SendView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var recipient = ""
    @State private var amountText = ""
    @State private var memo = ""
    @State private var fee: UInt64?
    @State private var reviewing = false
    @State private var busy = false
    @State private var problem: String?
    @State private var sentHash: String?

    private var amount: UInt64? { Amount.parse(amountText) }
    private var recipientOK: Bool { EgoAddress.isValid(recipient.trimmingCharacters(in: .whitespaces)) }
    private var memoOK: Bool { memo.utf8.count <= Transactions.maxMemoBytes }

    var body: some View {
        NavigationStack {
            Form {
                if let sentHash {
                    Section {
                        Label("Sent", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(Brand.mint)
                        Text(sentHash)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    } footer: {
                        Text("It shows as pending until the network confirms it, usually within a few seconds.")
                    }
                    Section { Button("Done") { dismiss() } }
                } else if reviewing, let amount {
                    Section("Check before sending") {
                        LabeledContent("To", value: shortAddress(recipient))
                        LabeledContent("Amount", value: "\(Amount.format(amount)) EGOC")
                        if let fee { LabeledContent("Network fee", value: "\(Amount.format(fee)) EGOC") }
                        if !memo.isEmpty { LabeledContent("Memo", value: memo) }
                    }
                    if let problem { Section { Text(problem).foregroundStyle(Brand.danger) } }
                    Section {
                        Button(busy ? "Sending…" : "Send \(Amount.format(amount)) EGOC") { Task { await send(amount) } }
                            .disabled(busy)
                        Button("Change something") { reviewing = false }
                            .disabled(busy)
                    } footer: {
                        Text("A payment can't be reversed once it's sent.")
                    }
                } else {
                    Section("Recipient") {
                        TextField("egot1…", text: $recipient)
                            .font(.system(.body, design: .monospaced))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        if !recipient.isEmpty && !recipientOK {
                            Text("That isn't an Ego address.").font(.caption).foregroundStyle(Brand.danger)
                        }
                        Button("Paste") { recipient = UIPasteboard.general.string ?? recipient }
                    }
                    Section("Amount") {
                        TextField("0.00", text: $amountText)
                            .keyboardType(.decimalPad)
                        if !amountText.isEmpty && (amount == nil || amount == 0) {
                            Text("Enter an amount with up to 6 decimals.").font(.caption).foregroundStyle(Brand.danger)
                        }
                    }
                    Section("Memo (optional)") {
                        TextField("What it's for", text: $memo)
                        if !memoOK { Text("The memo is too long.").font(.caption).foregroundStyle(Brand.danger) }
                    }
                    Section {
                        Button("Review") { reviewing = true }
                            .disabled(!recipientOK || (amount ?? 0) == 0 || !memoOK)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .screenBackground()
            .navigationTitle("Send EGOC")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
            .task { fee = await model.networkFee() }
        }
    }

    private func send(_ amount: UInt64) async {
        busy = true
        problem = nil
        do {
            sentHash = try await model.send(to: recipient.trimmingCharacters(in: .whitespaces), amount: amount, memo: memo)
        } catch {
            problem = model.message(for: error)
        }
        busy = false
    }
}

struct ReceiveView: View {
    let address: String
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 22) {
                Spacer()
                if let image = QRCode.image(for: address) {
                    Image(uiImage: image)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 240, height: 240)
                        .padding(14)
                        .background(Color.white)
                        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
                }
                Text(address)
                    .font(.system(.footnote, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .foregroundStyle(Brand.text)
                    .textSelection(.enabled)
                    .padding(.horizontal, 24)
                HStack(spacing: 12) {
                    Button(copied ? "Copied" : "Copy") {
                        UIPasteboard.general.string = address
                        copied = true
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    ShareLink(item: address) { Text("Share") }
                        .buttonStyle(SecondaryButtonStyle())
                }
                .padding(.horizontal, 24)
                Spacer()
            }
            .screenBackground()
            .navigationTitle("Receive EGOC")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
        }
    }
}

enum QRCode {
    static func image(for text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
              let cg = CIContext().createCGImage(output, from: output.extent)
        else { return nil }
        return UIImage(cgImage: cg)
    }
}
