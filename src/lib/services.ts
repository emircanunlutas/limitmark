export const services = [
  {
    id: "web",
    title: "Web Uygulaması Dayanıklılık Testi",
    question: "Trafik arttığında siteniz kullanılabilir kalıyor mu?",
    scope: "Web uygulamanızın kontrollü istek ve yük altındaki davranışını gözlemleriz. Kapsamda kararlaştırıldığında HTTP/HTTPS, TLS bağlantıları ve tarayıcı düzeyindeki senaryoları değerlendiririz.",
    result: "Belgelenen test koşullarında uygulama davranışı, erişilebilirlik ve gözlenen darboğazlar hakkında bulgular alırsınız.",
  },
  {
    id: "network",
    title: "Sunucu ve Ağ Servisi Dayanıklılık Testi",
    question: "Yük altında servisinize bağlantı kurulabiliyor ve servis işlevini sürdürebiliyor mu?",
    scope: "Sunucu ve ağ servislerinizin yük altındaki davranışını inceleriz. İlgili ve üzerinde anlaşılmış TCP/UDP veya servis düzeyindeki koşulları test planına dahil ederiz.",
    result: "Belgelenen koşullarda bağlantı kurulabilirliği, servis sürekliliği ve gözlenen sınırlar hakkında bulgular alırsınız.",
  },
  {
    id: "protection",
    title: "CDN / WAF / DDoS Koruma Doğrulaması",
    question: "Korumanız devredeyken gerçek kullanıcılar erişebiliyor mu?",
    scope: "Koruma katmanlarınızın davranışını birlikte belirlediğimiz koşullarda değerlendiririz. Filtrelemenin yanında normal kullanıcıların sisteme erişimini de ele alırız.",
    result: "Belgelenen koşullarda filtreleme ve koruma davranışı ile meşru erişime ilişkin gözlemleri alırsınız. Sonuçlar tüm koşullar için koruma garantisi değildir.",
  },
] as const;

export const serviceOptions = [
  ...services.map(({ id, title }) => ({ value: id, label: title })),
  { value: "unsure", label: "Karar veremiyorum / birlikte belirleyelim" },
];

export function resolveService(value: string | string[] | undefined) {
  return typeof value === "string" && serviceOptions.some((option) => option.value === value)
    ? value : "unsure";
}
