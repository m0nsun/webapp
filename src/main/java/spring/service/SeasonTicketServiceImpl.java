package spring.service;

import org.apache.tomcat.jni.Local;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import spring.entity.SeasonTicket;
import spring.exception.SeasonTicketNotFoundException;
import spring.repositories.PurchaseHistoryRepository;
import spring.repositories.SeasonTicketRepository;

import java.sql.Time;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

@Service
public class SeasonTicketServiceImpl implements SeasonTicketService {
    /*@Autowired
    private SeasonTicketRepository seasonTicketRepository;

    public List<SeasonTicket> findTickets()
    {
        return seasonTicketRepository.findAll();
    }
    public List<SeasonTicket> areForSale()
    {
        return seasonTicketRepository.findByIsForSale(true);
    }






    public List<SeasonTicket> areNotForSale()
    {
        return seasonTicketRepository.findByIsForSale(false);
    }

    public LocalTime getTimeDuration(String ticketType)
    {
        Optional<SeasonTicket> optionalSeasonTicket = seasonTicketRepository.findByTicketType(ticketType);
        if (optionalSeasonTicket.isPresent())
        {
            return optionalSeasonTicket.get().getTimeDuration();
        }
        throw new SeasonTicketNotFoundException("Season ticket is not found");
    }

    public SeasonTicket addSeasonTicket(SeasonTicket seasonTicket)
    {
        return seasonTicketRepository.save(seasonTicket);
    }

    public void changeIfIsForSale(SeasonTicket seasonTicket)
    {
        if (seasonTicket.getIsForSale())
        {
            if (purchaseHistoryRepository.findBySeasonTicket(seasonTicket))
            {
                seasonTicket.setIsForSale(false);
            }
            else
            {
                seasonTicketRepository.removeByTicketType(seasonTicket.getTicketType());
            }
        }
        else
        {
            seasonTicket.setIsForSale(true);
        }
    }*/
}
