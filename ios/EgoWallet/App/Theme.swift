import SwiftUI

enum Brand {
    static let ink = Color(red: 0.020, green: 0.027, blue: 0.047)
    static let card = Color(red: 0.055, green: 0.075, blue: 0.106)
    static let raised = Color(red: 0.086, green: 0.110, blue: 0.149)
    static let line = Color.white.opacity(0.08)
    static let text = Color(red: 0.961, green: 0.973, blue: 0.988)
    static let muted = Color(red: 0.604, green: 0.651, blue: 0.729)
    static let lime = Color(red: 0.824, green: 0.922, blue: 0.169)
    static let mint = Color(red: 0.0, green: 0.898, blue: 0.690)
    static let danger = Color(red: 1.0, green: 0.361, blue: 0.478)
    static let warning = Color(red: 1.0, green: 0.690, blue: 0.125)
}

struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(.headline, design: .rounded))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(Brand.lime.opacity(configuration.isPressed ? 0.8 : 1))
            .foregroundStyle(Brand.ink)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(.headline, design: .rounded))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(Brand.raised.opacity(configuration.isPressed ? 0.7 : 1))
            .foregroundStyle(Brand.text)
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Brand.line))
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

struct CardModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.card)
            .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Brand.line))
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

struct EgoMark: View {
    var size: CGFloat = 56

    var body: some View {
        Image("EgoMark")
            .resizable()
            .renderingMode(.template)
            .scaledToFit()
            .frame(width: size, height: size)
            .foregroundStyle(Brand.lime)
            .accessibilityLabel("Ego")
    }
}

struct SectionLabel: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 11, weight: .bold, design: .rounded))
            .tracking(1.2)
            .foregroundStyle(Brand.muted)
    }
}

struct ProblemBanner: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(.footnote)
            .foregroundStyle(Brand.warning)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Brand.warning.opacity(0.1))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

extension View {
    func card() -> some View {
        modifier(CardModifier())
    }

    func screenBackground() -> some View {
        background(Brand.ink.ignoresSafeArea())
    }
}

func shortAddress(_ address: String) -> String {
    address.count > 18 ? "\(address.prefix(10))…\(address.suffix(6))" : address
}

func relativeTime(_ ts: Int64) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(ts))
    let formatter = RelativeDateTimeFormatter()
    formatter.unitsStyle = .abbreviated
    return formatter.localizedString(for: date, relativeTo: Date())
}
