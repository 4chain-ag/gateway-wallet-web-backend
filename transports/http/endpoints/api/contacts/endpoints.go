package contacts

import (
	"net/http"
	"strconv"

	"github.com/bitcoin-sv/spv-wallet-web-backend/domain"
	"github.com/bitcoin-sv/spv-wallet-web-backend/domain/contacts"
	"github.com/bitcoin-sv/spv-wallet/models"

	"github.com/bitcoin-sv/spv-wallet-go-client/transports"
	"github.com/rs/zerolog"

	"github.com/bitcoin-sv/spv-wallet-web-backend/transports/http/auth"
	router "github.com/bitcoin-sv/spv-wallet-web-backend/transports/http/endpoints/routes"

	"github.com/gin-gonic/gin"
)

type handler struct {
	cService contacts.ContactsService
	log      *zerolog.Logger
}

// NewHandler creates new endpoint handler.
func NewHandler(s *domain.Services, log *zerolog.Logger) router.ApiEndpoints {
	return &handler{
		cService: *s.ContactsService,
		log:      log,
	}
}

// RegisterApiEndpoints registers routes that are part of service API.
func (h *handler) RegisterApiEndpoints(router *gin.RouterGroup) {
	user := router.Group("/contact")

	user.PUT("/:paymail", h.upsertContact)
	user.PATCH("/accepted/:paymail", h.acceptContact)
	user.PATCH("/rejected/:paymail", h.rejectContact)
	user.PATCH("/confirmed", h.confirmContact)
	user.GET("/all", h.getContacts)
	user.GET("/totp/:paymail", h.generateTotp)
}

// Get all user contacts.
//
//	@Summary Get all contacts.
//	@Tags contact
//	@Produce json
//	@Success 200 {object} []models.Contact
//	@Router /api/v1/contacts/all [get]
func (h *handler) getContacts(c *gin.Context) {
	page := c.Query("page")
	pageSize := c.Query("page_size")
	orderBy := c.Query("order")
	sort := c.Query("sort")

	pageNumber, err := strconv.Atoi(page)
	if err != nil {
		pageNumber = 1
	}

	pageSizeNumber, err := strconv.Atoi(pageSize)
	if err != nil {
		pageSizeNumber = 10
	}

	queryParam := transports.QueryParams{
		Page:          pageNumber,
		PageSize:      pageSizeNumber,
		OrderByField:  orderBy,
		SortDirection: sort,
	}

	// Get user transactions.
	txs, err := h.cService.GetContacts(c.Request.Context(), c.GetString(auth.SessionUserPaymail), &queryParam)
	if err != nil {
		h.log.Error().Msgf("An error occurred while trying to get a list of contacts: %s", err)
		c.JSON(http.StatusInternalServerError, "An error occurred while trying to get a list of contacts")
		return
	}

	c.JSON(http.StatusOK, txs)
}

// Upsert contact.
//
//	@Summary Create or update a contact.
//	@Tags contact
//	@Produce json
//	@Success 200
//	@Router /api/v1/contact/{paymail} [put]
//	@Param data body UpsertContact true "Upsert contact data"
func (h *handler) upsertContact(c *gin.Context) {
	paymail := c.Param("paymail")

	var req UpsertContact
	err := c.Bind(&req)
	if err != nil {
		h.log.Error().Msgf("Invalid payload: %s", err)
		c.JSON(http.StatusBadRequest, "Invalid request. Please check contact details")
		return
	}

	_, err = h.cService.UpsertContact(c.Request.Context(), c.GetString(auth.SessionUserPaymail), paymail, req.FullName, &req.Metadata)
	if err != nil {
		h.log.Error().Msgf("An error occurred while upserting the contact: %s", err)
		c.JSON(http.StatusBadRequest, "An error occurred while upserting the contact.")
		return
	}

	c.Status(http.StatusOK)
}

// Accept contact.
//
//	@Summary Accept a contact
//	@Tags contact
//	@Produce json
//	@Success 200
//	@Router /api/v1/contact/accepted/{paymail} [patch]
func (h *handler) acceptContact(c *gin.Context) {
	paymail := c.Param("paymail")

	err := h.cService.AcceptContact(c.Request.Context(), c.GetString(auth.SessionUserPaymail), paymail)
	if err != nil {
		h.log.Error().Msgf("An error occurred while accepting the contact: %s", err)
		c.JSON(http.StatusBadRequest, "An error occurred while accepting the contact.")
		return
	}

	c.Status(http.StatusOK)
}

// Reject contact.
//
//	@Summary Reject a contact
//	@Tags contact
//	@Produce json
//	@Success 200
//	@Router /api/v1/contact/rejected/{paymail} [patch]
func (h *handler) rejectContact(c *gin.Context) {
	paymail := c.Param("paymail")

	err := h.cService.RejectContact(c.Request.Context(), c.GetString(auth.SessionUserPaymail), paymail)
	if err != nil {
		h.log.Error().Msgf("An error occurred while rejecting the contact: %s", err)
		c.JSON(http.StatusBadRequest, "An error occurred while rejecting the contact.")
		return
	}

	c.Status(http.StatusOK)
}

// Confirm contact.
//
//	@Summary Confirm a contact
//	@Tags contact
//	@Produce json
//	@Success 200
//	@Router /api/v1/contact/confirmed [patch]
//	@Param data body ConfirmContact true "Confirm contact data"
func (h *handler) confirmContact(c *gin.Context) {
	var req ConfirmContact
	err := c.Bind(&req)
	if err != nil {
		h.log.Error().Msgf("Invalid payload: %s", err)
		c.JSON(http.StatusBadRequest, "Invalid request. Please check contact details and passcode")
		return
	}
	if req.Contact == nil {
		h.log.Error().Msgf("Invalid payload. Contact is not provided.", err)
		c.JSON(http.StatusBadRequest, "Invalid request. Contact is not provided")
		return
	}

	err = h.cService.ConfirmContact(c.Request.Context(), c.GetString(auth.SessionUserPaymail), req.Contact, req.Passcode)
	if err != nil {
		h.log.Error().Msgf("An error occurred while confirming the contact: %s", err)
		c.JSON(http.StatusBadRequest, "An error occurred while confirming the contact.")
		return
	}

	c.Status(http.StatusOK)
}

// Generate TOTP for contact.
//
//	@Summary Generate TOTP for contact.
//	@Tags contact
//	@Produce json
//	@Success 200
//	@Router /api/v1/contact/totp [put]
//	@Param data body models.Contact true "Contact details"
func (h *handler) generateTotp(c *gin.Context) {
	var contact models.Contact
	err := c.Bind(&contact)
	if err != nil {
		h.log.Error().Msgf("Invalid payload: %s", err)
		c.JSON(http.StatusBadRequest, "Invalid request. Please check contact details")
		return
	}

	passcode, err := h.cService.GenerateTotpForContact(c.Request.Context(), c.GetString(auth.SessionUserPaymail), &contact)
	if err != nil {
		h.log.Error().Msgf("An error occurred while generating TOTP for the contact: %s", err)
		c.JSON(http.StatusBadRequest, "An error occurred while generating TOTP for the contact.")
		return
	}

	c.JSON(http.StatusOK, TotpResponse{Passcode: passcode})
}
