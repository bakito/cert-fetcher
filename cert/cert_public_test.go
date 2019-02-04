package cert_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"

	"github.com/bakito/cert-fetcher/cert"
	"github.com/bakito/cert-fetcher/cert/test"

	. "github.com/bakito/cert-fetcher/cert"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cert", func() {

	Describe("Fetch certificates", func() {
		Context("Non TLS", func() {
			It("should return an error", func() {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				}))
				defer ts.Close()

				_, err := FetchCertificates(ts.URL)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("With TLS", func() {
			var ts *httptest.Server

			BeforeEach(func() {
				By("initializing TLS test server")

				ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				}))
			})
			AfterEach(func() {
				By("close TLS test server")
				ts.Close()
			})

			It("should have one valid cert", func() {
				certs, err := FetchCertificates(ts.URL)
				Expect(err).NotTo(HaveOccurred())
				Expect(certs).To(HaveLen(1))
			})

			It("print the correct fields of a cert", func() {
				out, revert := MockPrintTarget()
				defer revert()
				Print(ts.URL)
				Expect(out.String()).To(MatchRegexp("Certificate #0\\:\nSubject: .*\nIssuer\\: .*\nNotBefore\\: .*\nNotAfter\\: .*\n\n"))
			})
		})
	})

	Describe("IsToExport", func() {
		Context("empty slice", func() {
			It("should be true", func() {
				Expect(cert.IsToExport([]int{}, 1)).To(BeTrue())
			})
		})
		Context("non empty slice", func() {
			It("should be true if index is contained in slice", func() {
				Expect(cert.IsToExport([]int{1}, 1)).To(BeTrue())
			})
			It("should be false if index is not contained in slice", func() {
				Expect(cert.IsToExport([]int{1}, 2)).To(BeFalse())
			})
		})
	})

	Describe("Print Functions", func() {

		var out *bytes.Buffer
		var revert func()

		BeforeEach(func() {
			By("Mock log")
			out, revert = cert.MockPrintTarget()
		})
		AfterEach(func() {
			By("revert log")
			revert()
		})
		Context("Add", func() {
			It("should have added one cert", func() {
				cert.PrintAdd(1, test.NewCert())
				Expect(out.String()).To(Equal(" + Adding   certificate #1: GeoTrust Global CA\n"))
			})
		})
		Context("Skip", func() {
			It("should have skipped one cert", func() {
				cert.PrintSkip(1, test.NewCert())
				Expect(out.String()).To(Equal(" - Skipping certificate #1: GeoTrust Global CA \n"))
			})
		})
	})
})
